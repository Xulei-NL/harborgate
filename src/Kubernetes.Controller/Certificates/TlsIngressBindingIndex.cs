// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using k8s.Models;
using Microsoft.Extensions.Logging;
using Yarp.Kubernetes.Controller.Caching;

namespace Yarp.Kubernetes.Controller.Certificates;

internal readonly record struct TlsHostBinding(string Hostname, NamespacedName Secret);

internal record TlsHostBindingSnapshot(
    ImmutableDictionary<NamespacedName, ImmutableArray<TlsHostBinding>> BindingsByIngress,
    ImmutableDictionary<string, NamespacedName> SecretsByHost)
{
    public static TlsHostBindingSnapshot Empty { get; } = new(
        ImmutableDictionary<NamespacedName, ImmutableArray<TlsHostBinding>>.Empty,
        ImmutableDictionary<string, NamespacedName>.Empty.WithComparers(StringComparer.OrdinalIgnoreCase));

    public static TlsHostBindingSnapshot Create(
        IEnumerable<KeyValuePair<NamespacedName, ImmutableArray<TlsHostBinding>>> bindingsByIngress,
        Action<string, NamespacedName, NamespacedName> logCollision)
    {
        var bindingsMap = bindingsByIngress.ToImmutableDictionary();
        var secretsByHost = ImmutableDictionary.CreateBuilder<string, NamespacedName>(StringComparer.OrdinalIgnoreCase);

        // Use `OrderBy` and `ThenBy` because `NamespacedName` does not implement `IComparable.OrderBy`.
        foreach (var (namespacedName, bindings) in bindingsMap
                     .OrderBy(static pair => pair.Key.Namespace, StringComparer.Ordinal)
                     .ThenBy(static pair => pair.Key.Name, StringComparer.Ordinal))
        {
            foreach (var hostGroup in bindings.GroupBy(
                         static binding => binding.Hostname, StringComparer.OrdinalIgnoreCase))
            {
                if (secretsByHost.TryGetValue(hostGroup.Key, out var existingSecret))
                {
                    logCollision(hostGroup.Key, namespacedName, existingSecret);
                    continue;
                }

                var winningSecret = hostGroup.Select(static binding => binding.Secret)
                    .OrderBy(static secret => secret.ToString(), StringComparer.Ordinal).First();

                if (hostGroup.Skip(1).Any())
                {
                    logCollision(hostGroup.Key, namespacedName, winningSecret);
                }

                secretsByHost.Add(hostGroup.Key, winningSecret);
            }
        }

        return new TlsHostBindingSnapshot(bindingsMap, secretsByHost.ToImmutable());
    }
}

public class TlsIngressBindingIndex(ILogger<TlsIngressBindingIndex> logger) : ITlsIngressBindingIndex
{
    private TlsHostBindingSnapshot _snapshot = TlsHostBindingSnapshot.Empty;

    public bool TryGetSecret(string hostname, out NamespacedName secret)
    {
        if (string.IsNullOrWhiteSpace(hostname))
        {
            secret = default;
            return false;
        }

        var snapshot = Volatile.Read(ref _snapshot);
        if (snapshot.SecretsByHost.TryGetValue(hostname, out secret))
        {
            return true;
        }

        var wildcard = ToOneLabelWildcard(hostname);
        return wildcard is not null && snapshot.SecretsByHost.TryGetValue(wildcard, out secret);
    }

    public void ReplaceIngress(V1Ingress ingress)
    {
        var bindings = CreateBindings(ingress);
        Update(snapshot =>
            TlsHostBindingSnapshot.Create(snapshot.BindingsByIngress.SetItem(NamespacedName.From(ingress), bindings),
                LogCollision));
    }

    public void RemoveIngress(V1Ingress ingress) => Update(snapshot =>
        TlsHostBindingSnapshot.Create(snapshot.BindingsByIngress.Remove(NamespacedName.From(ingress)), LogCollision));

    public void SynchronizeLatestIngresses(IEnumerable<IngressData> ingresses) =>
        Update(_ => TlsHostBindingSnapshot.Create(
                ingresses.Select(ingress =>
                    new KeyValuePair<NamespacedName, ImmutableArray<TlsHostBinding>>(
                        new NamespacedName(ingress.Metadata.NamespaceProperty, ingress.Metadata.Name),
                        CreateBindings(ingress.Spec, ingress.Metadata.NamespaceProperty)
                    )
                ),
                LogCollision
            )
        );

    private void Update(Func<TlsHostBindingSnapshot, TlsHostBindingSnapshot> update)
    {
        while (true)
        {
            var current = Volatile.Read(ref _snapshot);
            var next = update(current);
            if (ReferenceEquals(current, Interlocked.CompareExchange(ref _snapshot, next, current)))
            {
                return;
            }
        }
    }

    private void LogCollision(string hostname, NamespacedName ingress, NamespacedName secret) =>
        logger.LogWarning(
            $"TLS hostname collision for {hostname}; Ingress {ingress} loses ownership to Secret {secret}.");

    private static ImmutableArray<TlsHostBinding> CreateBindings(V1Ingress ingress) =>
        CreateBindings(ingress.Spec, ingress.Namespace());

    private static ImmutableArray<TlsHostBinding> CreateBindings(V1IngressSpec specification, string @namespace)
    {
        var bindings = ImmutableArray.CreateBuilder<TlsHostBinding>();
        foreach (var tls in specification?.Tls ?? [])
        {
            // Skip the ingress TLS having no specified secret.
            if (string.IsNullOrWhiteSpace(tls.SecretName))
            {
                continue;
            }

            // Skip the ingress Tls having no specified hosts.
            if (tls.Hosts is not { Count: > 0 })
            {
                continue;
            }

            foreach (var host in tls.Hosts.Where(static host => !string.IsNullOrWhiteSpace(host)))
            {
                bindings.Add(new TlsHostBinding(host, new NamespacedName(@namespace, tls.SecretName)));
            }
        }

        return bindings.ToImmutable();
    }

    private static string ToOneLabelWildcard(string hostname)
    {
        var firstDot = hostname.IndexOf('.');
        return firstDot > 0 && firstDot < hostname.Length - 1
            ? "*" + hostname[firstDot..]
            : null;
    }
}
