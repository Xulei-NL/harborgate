// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography.X509Certificates;

namespace Yarp.Kubernetes.Controller.Certificates;

public interface ITlsSecretCertificateStore
{
    public bool TryAcquire(NamespacedName secret, out TlsSecretCertificateLease lease);

    public void Replace(NamespacedName secret, X509Certificate2 leafCertificate,
        X509Certificate2Collection intermediateCertificates);

    public void Remove(NamespacedName secret);
}
