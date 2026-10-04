// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Net.Security;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Yarp.Kubernetes.Controller.Certificates;

internal class ServerCertificateSelector : IServerCertificateSelector, IDisposable
{
    private readonly TlsSecretCertificateLease _defaultTlsSecretCertificateLease;
    private readonly SslStreamCertificateContext _defaultSslStreamCertificateContext;
    private readonly ITlsIngressBindingIndex _tlsIngressBindingIndex;
    private readonly ITlsSecretCertificateStore _tlsSecretCertificateStore;
    private readonly ILogger<ServerCertificateSelector> _logger;

    public ServerCertificateSelector(IOptions<YarpOptions> options,
        ITlsIngressBindingIndex tlsIngressBindingIndex, ITlsSecretCertificateStore tlsSecretCertificateStore,
        ILogger<ServerCertificateSelector> logger)
    {
        _logger = logger;
        _tlsSecretCertificateStore = tlsSecretCertificateStore;

        (_defaultTlsSecretCertificateLease, _defaultSslStreamCertificateContext) =
            GetDefaultSslStreamCertificateContext(options.Value);
        _tlsIngressBindingIndex = tlsIngressBindingIndex;
    }

    public SslStreamCertificateContext GetSslStreamCertificateContext(string domainName)
    {
        if (_tlsIngressBindingIndex.TryGetSecret(domainName, out var secret) &&
            _tlsSecretCertificateStore.TryAcquire(secret, out var lease) && lease is not null)
        {
            using (lease)
            {
                return SslStreamCertificateContext.Create(
                    target: lease.LeafCertificate,
                    additionalCertificates: lease.IntermediateCertificates,
                    offline: true);
            }
        }

        return _defaultSslStreamCertificateContext;
    }

    private (TlsSecretCertificateLease, SslStreamCertificateContext) GetDefaultSslStreamCertificateContext(
        YarpOptions options)
    {
        var namespaceAndName = options.DefaultSslCertificate.Split('/');
        if (namespaceAndName.Length != 2 || string.IsNullOrWhiteSpace(namespaceAndName[0]) ||
            string.IsNullOrWhiteSpace(namespaceAndName[1]))
        {
            _logger.LogWarning("The {OptionName} option must be in the format '<namespace>/<secret-name>'.",
                nameof(YarpOptions.DefaultSslCertificate));
            return (null, null);
        }

        var secretNamespacedName = new NamespacedName(namespaceAndName[0], namespaceAndName[1]);
        return GetDefaultSslStreamCertificateContextFromStore(secretNamespacedName);
    }

    private (TlsSecretCertificateLease, SslStreamCertificateContext) GetDefaultSslStreamCertificateContextFromStore(
        NamespacedName defaultSecret)
    {
        if (_tlsSecretCertificateStore.TryAcquire(defaultSecret, out var lease))
        {
            var defaultSslStreamCertificateContext =
                SslStreamCertificateContext.Create(lease.LeafCertificate,
                    lease.IntermediateCertificates, true);

            return (lease, defaultSslStreamCertificateContext);
        }

        return (null, null);
    }

    public void Dispose()
    {
        _defaultTlsSecretCertificateLease?.Dispose();
    }
}
