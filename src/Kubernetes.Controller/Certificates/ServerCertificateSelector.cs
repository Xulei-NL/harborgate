// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using k8s;
using k8s.Models;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Yarp.Kubernetes.Controller.Certificates;

internal class ServerCertificateSelector : IServerCertificateSelector
{
    private readonly List<NamespacedName> _catchAllTlsCache = [];
    private readonly object _sync = new();
    private readonly Dictionary<NamespacedName, X509Certificate2> _certificateCache = new();
    private readonly Dictionary<string, List<NamespacedName>> _hostNameTlsCache = new();
    private readonly Dictionary<NamespacedName, IngressTlsPropertyTracker> _ingressTlsCache = new();

    private readonly ILogger<ServerCertificateSelector> _logger;

    private readonly string _defaultSslCertificateSecret;
    private X509Certificate2 _defaultCertificate;

    public ServerCertificateSelector(IOptions<YarpOptions> options, ILogger<ServerCertificateSelector> logger)
    {
        ArgumentNullException.ThrowIfNull(options?.Value);

        _logger = logger;
        _defaultSslCertificateSecret = options.Value.DefaultSslCertificate;
    }

    public void AddCertificate(NamespacedName certificateName, X509Certificate2 certificate)
    {
        lock (_sync)
        {
            _certificateCache[certificateName] = certificate;
            if (certificateName.ToString() == _defaultSslCertificateSecret)
            {
                _defaultCertificate = certificate;
            }
        }
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

            if (TryGetExactMatchCertificate(domainName, out var chosenCertificate))
            {
                return chosenCertificate;
            }

            if (TryGetWildcardCertificate(domainName, out chosenCertificate))
            {
                return chosenCertificate;
            }

            _logger.LogDebug($"No certificate matched {domainName}; using default certificate.");

            if (TryGetDefaultCertificate(out chosenCertificate))
            {
                return chosenCertificate;
            }

            _logger.LogWarning($"No default certificate is loaded yet; cannot complete TLS for {domainName}");
            return null;
        }
    }

    private bool TryGetWildcardCertificate(string domainName, out X509Certificate2 certificate)
    {
        certificate = null;

        var wildcardDomainName = ConstructWildcardDomainName(domainName);
        if (wildcardDomainName is null || !TryGetExactMatchCertificate(wildcardDomainName, out var wildcardCertificate))
        {
            return false;
        }

        certificate = wildcardCertificate;
        return true;
    }

    private bool TryGetDefaultCertificate(out X509Certificate2 certificate)
    {
        certificate = null;

        if (_defaultCertificate is null)
        {
            return false;
        }

        certificate = _defaultCertificate;
        return true;
    }

    public void RemoveCertificate(NamespacedName certificateName)
    {
        lock (_sync)
        {
            _certificateCache.Remove(certificateName, out _);
            if (certificateName.ToString() == _defaultSslCertificateSecret)
            {
                _defaultCertificate = null;
            }
        }
    }

    public void UpdateIngressTls(WatchEventType eventType, V1Ingress ingress)
    {
        var ingressNamespacedName = NamespacedName.From(ingress);

        lock (_sync)
        {
            switch (eventType)
            {
                case WatchEventType.Added:
                case WatchEventType.Modified:
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
                                ingressTlsProperties.Add(new IngressTlsProperty(
                                    Type: IngressTlsType.CatchAllCertificate,
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
                        break;
                    }
                case WatchEventType.Deleted:
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
                        break;
                    }
                case WatchEventType.Error:
                case WatchEventType.Bookmark:
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(eventType), eventType, "Unknown event.");
            }
        }
    }

    private bool TryGetExactMatchCertificate(string domainName, out X509Certificate2 certificate)
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
}
