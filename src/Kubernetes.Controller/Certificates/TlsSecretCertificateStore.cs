// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Yarp.Kubernetes.Controller.Certificates;

/// <summary>
/// Holds the current TLS certificate chain for each Kubernetes TLS secret and disposes chains once it is safe to do so.
/// </summary>
/// <remarks>
/// <para>
/// When a secret is replaced or removed, its old chain is <em>retired</em>: new <see cref="TryAcquire"/> calls stop
/// returning it immediately, but it is not disposed until both of the following hold:
/// </para>
/// <list type="number">
/// <item>
/// <description>
/// <b>No active leases.</b> A <see cref="TlsSecretCertificateLease"/> keeps the chain alive while the caller holds it.
/// This covers usage the caller can bracket with acquire/dispose.
/// </description>
/// </item>
/// <item>
/// <description>
/// <b>The retirement grace period has elapsed.</b> This covers usage that outlives the lease and that the caller cannot
/// observe. For example, Kestrel's <c>ServerCertificateSelector</c> returns the certificate synchronously, so the lease
/// is released when the callback returns, yet <c>SslStream</c> keeps using the certificate (including its private key)
/// for the rest of the TLS handshake and may cache credentials built from it. No lease can cover that window, so the
/// grace period is the only protection.
/// </description>
/// </item>
/// </list>
/// <para>
/// Retired entries are kept in a FIFO queue ordered by retirement time. A periodic timer (and every
/// <see cref="Replace"/>/<see cref="Remove"/>) dequeues entries whose grace period has elapsed and marks them as such.
/// Whichever condition is satisfied last triggers disposal: either the grace-period sweep or the release of the last
/// lease.
/// </para>
/// </remarks>
public class TlsSecretCertificateStore : ITlsSecretCertificateStore, IDisposable
{
    private readonly TimeSpan _certificateRetirementGracePeriod;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TlsSecretCertificateStore> _logger;

    private readonly object _sync = new();
    private readonly Queue<RetiredCertificate> _retiredCertificates = new();
    private readonly ITimer _retirementCleanupTimer;

    private ImmutableDictionary<NamespacedName, CertificateEntry> _certificatesBySecret =
        ImmutableDictionary<NamespacedName, CertificateEntry>.Empty;

    private bool _isDisposed;

    public TlsSecretCertificateStore(
        ILogger<TlsSecretCertificateStore> logger,
        TimeProvider timeProvider = null,
        TimeSpan? certificateRetirementGracePeriod = null)
    {
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _certificateRetirementGracePeriod = certificateRetirementGracePeriod ?? TimeSpan.FromMinutes(10);

        _retirementCleanupTimer = _timeProvider.CreateTimer(
            _ => OnRetirementCleanupTimer(), null,
            _certificateRetirementGracePeriod, _certificateRetirementGracePeriod
        );
    }

    public bool TryAcquire(NamespacedName secret, out TlsSecretCertificateLease lease)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        var snapshot = Volatile.Read(ref _certificatesBySecret);
        while (true)
        {
            if (snapshot is null || !snapshot.TryGetValue(secret, out var certificateEntry))
            {
                lease = null;
                return false;
            }

            if (certificateEntry.TryAcquire())
            {
                lease = new TlsSecretCertificateLease(certificateEntry);
                return true;
            }

            // Entry was retired, so the dictionary has already moved on; retry with the latest snapshot.
            var latest = Volatile.Read(ref _certificatesBySecret);
            if (ReferenceEquals(latest, snapshot))
            {
                lease = null;
                return false;
            }

            snapshot = latest;
        }
    }

    public void Replace(NamespacedName secret, TlsCertificateChain tlsCertificateChain)
    {
        ArgumentNullException.ThrowIfNull(tlsCertificateChain);

        var entry = new CertificateEntry(tlsCertificateChain);
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);

            _certificatesBySecret.TryGetValue(secret, out var replaced);
            Volatile.Write(ref _certificatesBySecret, _certificatesBySecret.SetItem(secret, entry));
            if (replaced is not null)
            {
                Retire(replaced);
            }

            DequeueElapsedRetirements();
        }
    }

    public void Remove(NamespacedName secret)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);

            if (_certificatesBySecret.TryGetValue(secret, out var removed))
            {
                Volatile.Write(ref _certificatesBySecret, _certificatesBySecret.Remove(secret));
                Retire(removed);

                DequeueElapsedRetirements();
            }
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_isDisposed)
            {
                return;
            }

            _isDisposed = true;
            _retirementCleanupTimer.Dispose();
            foreach (var certificate in _certificatesBySecret.Values)
            {
                certificate.Retire();
                certificate.MarkGracePeriodElapsed();
            }

            while (_retiredCertificates.TryDequeue(out var retiredCertificate))
            {
                retiredCertificate.Entry.Retire();
                retiredCertificate.Entry.MarkGracePeriodElapsed();
            }

            _certificatesBySecret = ImmutableDictionary<NamespacedName, CertificateEntry>.Empty;
        }
    }

    private void Retire(CertificateEntry entry)
    {
        entry.Retire();
        _retiredCertificates.Enqueue(new RetiredCertificate(entry, _timeProvider.GetUtcNow()));
    }

    private void OnRetirementCleanupTimer()
    {
        try
        {
            lock (_sync)
            {
                if (!_isDisposed)
                {
                    DequeueElapsedRetirements();
                }
            }
        }
        catch (Exception exception)
        {
            // Timer callbacks run on the thread pool; an unhandled exception would crash the process.
            _logger.LogError(exception, "Failed to release retired TLS certificates");
        }
    }

    /// <summary>
    /// Ends the grace period of every retired entry that was retired at least
    /// <see cref="_certificateRetirementGracePeriod"/> ago and removes it from the queue.
    /// </summary>
    /// <remarks>
    /// This only ends the grace period; it does not force disposal. An entry that still has active leases is
    /// dequeued but stays alive, and is disposed by <see cref="CertificateEntry.Release"/> when its last lease is
    /// released. After dequeuing, the store no longer references the entry; the outstanding leases do.
    /// Must be called while holding <see cref="_sync"/>.
    /// </remarks>
    private void DequeueElapsedRetirements()
    {
        Debug.Assert(Monitor.IsEntered(_sync), "Caller must hold _sync.");

        var retirementCutoff = _timeProvider.GetUtcNow() - _certificateRetirementGracePeriod;
        while (_retiredCertificates.TryPeek(out var retiredCertificate) && retiredCertificate.RetiredAt <= retirementCutoff)
        {
            _retiredCertificates.Dequeue().Entry.MarkGracePeriodElapsed();
        }
    }

    private readonly record struct RetiredCertificate(CertificateEntry Entry, DateTimeOffset RetiredAt);
}

/// <summary>
/// Tracks the lifetime of one <see cref="TlsCertificateChain"/> and disposes it when it is retired, its grace period
/// has elapsed, and no leases remain. See <see cref="TlsSecretCertificateStore"/> for why both leases and a grace
/// period are needed.
/// </summary>
internal sealed class CertificateEntry(TlsCertificateChain tlsCertificateChain)
{
    private readonly object _sync = new();

    private int _activeLeaseCount;
    private bool _isRetired;
    private bool _isRetirementGracePeriodElapsed;
    private bool _isChainDisposed;

    public X509Certificate2 LeafCertificate { get; } = tlsCertificateChain.LeafCertificate;
    public X509Certificate2Collection IntermediateCertificates { get; } = tlsCertificateChain.IntermediateCertificates;

    public bool TryAcquire()
    {
        lock (_sync)
        {
            if (_isRetired)
            {
                return false;
            }

            ++_activeLeaseCount;
            return true;
        }
    }

    public void Release()
    {
        lock (_sync)
        {
            if (_activeLeaseCount <= 0)
            {
                throw new InvalidOperationException("Cannot release a certificate lease that was not acquired.");
            }

            --_activeLeaseCount;
            TryDisposeChain();
        }
    }

    public void Retire()
    {
        lock (_sync)
        {
            _isRetired = true;
        }
    }

    public void MarkGracePeriodElapsed()
    {
        lock (_sync)
        {
            _isRetirementGracePeriodElapsed = true;
            TryDisposeChain();
        }
    }

    /// <summary>
    /// Disposes the chain if it is retired, its grace period has elapsed, and no leases remain.
    /// Called from both <see cref="Release"/> and <see cref="MarkGracePeriodElapsed"/>, so whichever happens last
    /// performs the disposal. Must be called while holding <see cref="_sync"/>.
    /// </summary>
    /// <returns><c>true</c> if this call disposed the chain; otherwise <c>false</c>.</returns>
    private bool TryDisposeChain()
    {
        if (_activeLeaseCount != 0 || !_isRetired || !_isRetirementGracePeriodElapsed || _isChainDisposed)
        {
            return false;
        }

        _isChainDisposed = true;
        tlsCertificateChain.Dispose();
        return true;
    }
}

/// <summary>
/// Keeps a certificate chain from being disposed while held. Always dispose the lease; otherwise a retired chain is
/// never disposed explicitly and its native resources are only reclaimed by the certificates' finalizers.
/// </summary>
public sealed class TlsSecretCertificateLease : IDisposable
{
    private CertificateEntry _certificateEntry;

    internal TlsSecretCertificateLease(CertificateEntry certificateEntry)
    {
        _certificateEntry = certificateEntry;
    }

    public X509Certificate2 LeafCertificate =>
        (_certificateEntry ?? throw new ObjectDisposedException(nameof(TlsSecretCertificateLease))).LeafCertificate;

    public X509Certificate2Collection IntermediateCertificates =>
        (_certificateEntry ?? throw new ObjectDisposedException(nameof(TlsSecretCertificateLease)))
        .IntermediateCertificates;

    public void Dispose() => Interlocked.Exchange(ref _certificateEntry, null)?.Release();
}
