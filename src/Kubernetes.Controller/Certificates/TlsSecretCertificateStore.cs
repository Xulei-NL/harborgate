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

public class TlsSecretCertificateStore : ITlsSecretCertificateStore, IDisposable
{
    private readonly TimeSpan _certificateRetirementGracePeriod;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TlsSecretCertificateStore> _logger;

    private readonly object _sync = new();
    private readonly Queue<RetiredCertificate> _retiredCertificates = new();
    private readonly Timer _retirementCleanupTimer;

    private ImmutableDictionary<NamespacedName, CertificateEntry> _certificatesBySecret =
        ImmutableDictionary<NamespacedName, CertificateEntry>.Empty;

    private bool _isDisposed;

    public TlsSecretCertificateStore(
        ILogger<TlsSecretCertificateStore> logger,
        TimeProvider timeProvider = null,
        TimeSpan? certificateRetirementGracePeriod = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _certificateRetirementGracePeriod = certificateRetirementGracePeriod ?? TimeSpan.FromMinutes(10);

        _retirementCleanupTimer = new Timer(
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

            ReleaseCertificatesPastGracePeriod();
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

                ReleaseCertificatesPastGracePeriod();
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
                    ReleaseCertificatesPastGracePeriod();
                }
            }
        }
        catch (Exception exception)
        {
            // Timer callbacks run on the thread pool; an unhandled exception would crash the process.
            _logger.LogError(exception, "Failed to release retired TLS certificates");
        }
    }

    private void ReleaseCertificatesPastGracePeriod()
    {
        Debug.Assert(Monitor.IsEntered(_sync), "Caller must hold _sync.");

        var threshold = _timeProvider.GetUtcNow() - _certificateRetirementGracePeriod;
        while (_retiredCertificates.TryPeek(out var retiredCertificate) && retiredCertificate.RetiredAt <= threshold)
        {
            _retiredCertificates.Dequeue().Entry.MarkGracePeriodElapsed();
        }
    }

    private readonly record struct RetiredCertificate(CertificateEntry Entry, DateTimeOffset RetiredAt);
}

internal sealed class CertificateEntry(TlsCertificateChain tlsCertificateChain)
{
    private readonly object _sync = new();

    private int _activeLeaseCount;
    private bool _isRetired;
    private bool _isRetirementGracePeriodElapsed;
    private bool _isDisposed;

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
            ReleaseCertificatesIfEligible();
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
            ReleaseCertificatesIfEligible();
        }
    }

    ///<summary>
    /// Must be called under `_sync`.
    /// </summary>
    private void ReleaseCertificatesIfEligible()
    {
        if (_activeLeaseCount != 0 || !_isRetired || !_isRetirementGracePeriodElapsed || _isDisposed)
        {
            return;
        }

        _isDisposed = true;
        tlsCertificateChain.Dispose();
    }
}

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
