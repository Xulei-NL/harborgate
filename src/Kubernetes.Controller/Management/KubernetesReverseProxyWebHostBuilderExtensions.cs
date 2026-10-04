// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Net.Security;
using System.Security.Authentication;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Yarp.Kubernetes.Controller.Certificates;

namespace Microsoft.AspNetCore.Hosting;

/// <summary>
/// Extensions for <see cref="IWebHostBuilder"/>
/// used to register the Kubernetes-based ReverseProxy's components.
/// </summary>
public static class KubernetesReverseProxyWebHostBuilderExtensions
{
    /// <summary>
    /// Configures Kestrel for SNI-based certificate selection using Kubernetes Ingress TLS annotations and Kubernetes Secrets.
    /// </summary>
    /// <param name="builder">The web host builder.</param>
    /// <returns>The same <see cref="IWebHostBuilder"/> for chaining.</returns>
    public static IWebHostBuilder UseKubernetesReverseProxyCertificateSelector(this IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ConfigureKestrel(kestrelOptions =>
        {
            var selector = kestrelOptions.ApplicationServices.GetService<IServerCertificateSelector>();
            kestrelOptions.ListenAnyIP(8080, listenOptions =>
            {
                if (selector is null)
                {
                    throw new InvalidOperationException(
                        "Missing required services. Did you call '.AddKubernetesReverseProxy()' when configuring services?");
                }

                listenOptions.UseHttps(new TlsHandshakeCallbackOptions
                {
                    OnConnection = tlsHandshakeCallbackContext => new ValueTask<SslServerAuthenticationOptions>(
                        new SslServerAuthenticationOptions
                        {
                            ServerCertificateContext =
                                selector.GetSslStreamCertificateContext(
                                    tlsHandshakeCallbackContext.ClientHelloInfo.ServerName),
                            EnabledSslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12,
                            ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]
                        })
                });
            });
        });

        return builder;
    }
}
