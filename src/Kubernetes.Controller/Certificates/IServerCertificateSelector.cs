// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Security;
using Microsoft.AspNetCore.Connections;

namespace Yarp.Kubernetes.Controller.Certificates;

/// <summary>
/// A mechanism for obtaining server certificates dynamically based on the SNI domain name.
/// </summary>
public interface IServerCertificateSelector
{
    public SslStreamCertificateContext GetSslStreamCertificateContext(ConnectionContext connectionContext, string domainName);
}
