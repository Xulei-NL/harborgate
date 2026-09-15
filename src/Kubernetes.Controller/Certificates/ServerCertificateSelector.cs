// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using k8s;
using k8s.Models;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Yarp.Kubernetes.Controller.Caching;

namespace Yarp.Kubernetes.Controller.Certificates;

internal class ServerCertificateSelector : IServerCertificateSelector
{
    private const string DefaultCertificatePosition = "Kestrel:Certificates:Default:Path";
    private const string DefaultCertificatePasswordPosition = "Kestrel:Certificates:Default:Password";

    private readonly List<NamespacedName> _catchAllTlsCache = [];
    private readonly object _sync = new();
    private readonly Dictionary<NamespacedName, X509Certificate2> _certificateCache = new();
    private readonly Dictionary<string, List<NamespacedName>> _hostNameTlsCache = new();
    private readonly Dictionary<NamespacedName, IngressTlsPropertyTracker> _ingressTlsCache = new();

    private readonly ILogger<ServerCertificateSelector> _logger;

    private X509Certificate2 _defaultCertificate;

    public ServerCertificateSelector(IConfiguration configuration, ILogger<ServerCertificateSelector> logger)
    {
        _logger = logger;

        LoadDefaultCertificate(configuration);
    }

    private void LoadDefaultCertificate(IConfiguration configuration)
    {
        var defaultCertificatePath = configuration[DefaultCertificatePosition];
        if (string.IsNullOrWhiteSpace(defaultCertificatePath))
        {
            throw new InvalidOperationException(
                $"Default server certificate path is not configured. Set '{DefaultCertificatePosition}'.");
        }

        var defaultCertificatePasswordPath = configuration[DefaultCertificatePasswordPosition];
        try
        {
            _defaultCertificate =
                new X509Certificate2(defaultCertificatePath, defaultCertificatePasswordPath);
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                $"Failed to load the default server certificate from '{defaultCertificatePath}'. Verify the file exists and the password configured at '{DefaultCertificatePasswordPosition}'",
                exception);
        }
    }

    public void AddCertificate(NamespacedName certificateName, X509Certificate2 certificate)
    {
        lock (_sync)
        {
            _certificateCache[certificateName] = certificate;
        }
    }

    private bool TryGetCertificate(string domainName, out X509Certificate2 certificate)
    {
        if (_hostNameTlsCache.TryGetValue(domainName, out var namespacedNameList))
        {
            foreach (var namespacedName in namespacedNameList)
            {
                if (_certificateCache.TryGetValue(namespacedName, out var candidate))
                {
                    certificate = candidate;
                    return true;
                }
            }
        }

        certificate = null!;
        return false;
    }

    private static string ConstructWildcardDomainName(string domainName)
    {
        var firstDotIndex = domainName.IndexOf('.');

        return firstDotIndex < 0 ? null : "*" + domainName[firstDotIndex..];
    }

    public X509Certificate2 GetCertificate(ConnectionContext connectionContext, string domainName)
    {
        lock (_sync)
        {
            if (string.IsNullOrEmpty(domainName))
            {
                _logger.LogDebug("No SNI domain name was provided. using default certificate.");
                return _defaultCertificate;
            }

            if (TryGetCertificate(domainName, out var certificate))
            {
                return certificate;
            }

            var wildcardDomainName = ConstructWildcardDomainName(domainName);
            if (wildcardDomainName is not null && TryGetCertificate(wildcardDomainName, out var wildcardCertificate))
            {
                return wildcardCertificate;
            }

            _logger.LogDebug($"No certificate matched {domainName}; using default certificate.");
            return _defaultCertificate;
        }
    }

    public void RemoveCertificate(NamespacedName certificateName)
    {
        lock (_sync)
        {
            _certificateCache.Remove(certificateName, out _);
        }
    }

    public void UpdateIngressTls(WatchEventType eventType, V1Ingress ingress)
    {
        var ingressNamespacedName = NamespacedName.From(ingress);

        if (eventType == WatchEventType.Added || eventType == WatchEventType.Modified)
        {
            var ingressTlsProperties = new List<IngressTlsProperty>();

            foreach (var tls in ingress.Spec?.Tls ?? [])
            {
                var certificateSecretName = tls.SecretName;
                if (string.IsNullOrWhiteSpace(certificateSecretName))
                {
                    // Fall back to using default certificate so no need to read the TLS host name configurations.
                    continue;
                }

                var secretNamespacedName = new NamespacedName(ingress.Namespace(), certificateSecretName);

                var hostNames = tls.Hosts;
                if (hostNames is null)
                {
                    // Fall back to using catch-all certificate.
                    _catchAllTlsCache.Add(secretNamespacedName);
                    ingressTlsProperties.Add(new IngressTlsProperty(Type: IngressTlsType.CatchAllCertificate,
                        SecretNamespacedName: secretNamespacedName, HostName: null));
                    continue;
                }

                foreach (var hostName in hostNames)
                {
                    if (_hostNameTlsCache.TryGetValue(hostName, out var secretNamespacedNames))
                    {
                        secretNamespacedNames.Add(secretNamespacedName);
                    }
                    else
                    {
                        _hostNameTlsCache[hostName] = [secretNamespacedName];
                    }
                    ingressTlsProperties.Add(new IngressTlsProperty(Type: IngressTlsType.NormalCertificate,
                        SecretNamespacedName: secretNamespacedName, HostName: hostName));
                }
            }

            _ingressTlsCache[ingressNamespacedName] = new IngressTlsPropertyTracker(ingressTlsProperties);
        }
        else if (eventType == WatchEventType.Deleted)
        {
            if (_ingressTlsCache.TryGetValue(ingressNamespacedName,
                    out var certificateSecretAndHostNames))
            {
                foreach (var (tlsType, secretNamespacedName, hostName) in certificateSecretAndHostNames
                             .IngressTlsProperties ?? [])
                {
                    if (_hostNameTlsCache.TryGetValue(hostName, out var secretNames))
                    {
                        secretNames.Remove(secretNamespacedName);
                        if (secretNames.Count == 0)
                        {
                            _hostNameTlsCache.Remove(hostName);
                        }
                    }
                }
            }

            _ingressTlsCache.Remove(ingressNamespacedName);
        }
    }
}
