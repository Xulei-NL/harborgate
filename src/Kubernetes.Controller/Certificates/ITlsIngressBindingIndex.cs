// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using k8s.Models;
using Yarp.Kubernetes.Controller.Caching;

namespace Yarp.Kubernetes.Controller.Certificates;

public interface ITlsIngressBindingIndex
{
    public bool TryGetSecret(string hostname, out NamespacedName secret);
    public void ReplaceIngress(V1Ingress ingress);
    public void RemoveIngress(V1Ingress ingress);
    public void SynchronizeLatestIngresses(IEnumerable<IngressData> ingresses);
}
