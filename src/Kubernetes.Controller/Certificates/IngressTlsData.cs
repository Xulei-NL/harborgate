// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Immutable;

namespace Yarp.Kubernetes.Controller.Certificates;

public enum IngressTlsType
{
    DefaultCertificate = 0,
    CatchAllCertificate = 1,
    NormalCertificate = 2
}
public record IngressTlsProperty(IngressTlsType Type, NamespacedName SecretNamespacedName, string HostName);

public record IngressTlsPropertyTracker(ImmutableArray<IngressTlsProperty> IngressTlsProperties);
