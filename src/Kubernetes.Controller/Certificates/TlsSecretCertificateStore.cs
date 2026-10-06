// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Yarp.Kubernetes.Controller.Certificates;

public class TlsSecretCertificateStore : ITlsSecretCertificateStore, IDisposable
{
    private static readonly TimeSpan _certificateRetirementGracePeriod = TimeSpan.FromMinutes(10);
    private readonly TimeProvider _timeProvider = TimeProvider.System;

    private readonly object _sync = new();
    private readonly Queue<RetiredCertificate> _retiredCertificates = new();
    private readonly Timer _retirementCleanupTimer;

    private ImmutableDictionary<NamespacedName, CertificateEntry> _certificatesBySecret =
        ImmutableDictionary<NamespacedName, CertificateEntry>.Empty;

    private bool _isDisposed;

    public TlsSecretCertificateStore()
    {
        _retirementCleanupTimer = new Timer(
            _ => OnRetirementCleanupTimer(), null,
            _certificateRetirementGracePeriod, _certificateRetirementGracePeriod
        );
    }

    public bool TryAcquire(NamespacedName secret, out TlsSecretCertificateLease lease)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (!_certificatesBySecret.TryGetValue(secret, out var certificateEntry) || !certificateEntry.TryAcquire())
            {
                lease = null;
                return false;
            }

            lease = new TlsSecretCertificateLease(certificateEntry);
            return true;
        }
    }

    public void Replace(NamespacedName secret, X509Certificate2 leafCertificate,
        X509Certificate2Collection intermediateCertificates)
    {
        ArgumentNullException.ThrowIfNull(leafCertificate);
        ArgumentNullException.ThrowIfNull(intermediateCertificates);

        var entry = new CertificateEntry(leafCertificate, intermediateCertificates);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_certificatesBySecret.TryGetValue(secret, out var replaced))
            {
                Retire(replaced);
            }

            _certificatesBySecret = _certificatesBySecret.SetItem(secret, entry);
            AllowDisposalOfExpiredCertificatesUnderLock();
        }
    }

    public void Remove(NamespacedName secret)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_certificatesBySecret.TryGetValue(secret, out var removed))
            {
                Retire(removed);
                _certificatesBySecret = _certificatesBySecret.Remove(secret);
                AllowDisposalOfExpiredCertificatesUnderLock();
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
                certificate.AllowDisposal();
            }

            while (_retiredCertificates.TryDequeue(out var retiredCertificate))
            {
                retiredCertificate.Entry.Retire();
                retiredCertificate.Entry.AllowDisposal();
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
        lock (_sync)
        {
            if (!_isDisposed)
            {
                AllowDisposalOfExpiredCertificatesUnderLock();
            }
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_isDisposed, this);

    private void AllowDisposalOfExpiredCertificatesUnderLock()
    {
        var threshold = _timeProvider.GetUtcNow() - _certificateRetirementGracePeriod;
        while (_retiredCertificates.TryPeek(out var retiredCertificate) && retiredCertificate.RetiredAt <= threshold)
        {
            _retiredCertificates.Dequeue().Entry.AllowDisposal();
        }
    }

    private readonly record struct RetiredCertificate(CertificateEntry Entry, DateTimeOffset RetiredAt);
}

public class CertificateEntry(X509Certificate2 leafCertificate, X509Certificate2Collection intermediateCertificates)
{
    private readonly object _sync = new();
    private int _activeLeaseCount;
    private bool _isRetired;
    private bool _isRetirementGracePeriodElapsed;
    private bool _isDisposed;

    public X509Certificate2 LeafCertificate { get; } = leafCertificate;
    public X509Certificate2Collection IntermediateCertificates { get; } = intermediateCertificates;

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
            --_activeLeaseCount;
            DisposeIfEligible();
        }
    }

    public void Retire()
    {
        lock (_sync)
        {
            _isRetired = true;
        }
    }

    public void AllowDisposal()
    {
        lock (_sync)
        {
            _isRetirementGracePeriodElapsed = true;
            DisposeIfEligible();
        }
    }

    private void DisposeIfEligible()
    {
        if (_activeLeaseCount != 0 || !_isRetired || !_isRetirementGracePeriodElapsed || _isDisposed)
        {
            return;
        }

        _isDisposed = true;

        LeafCertificate.Dispose();
        foreach (var certificate in IntermediateCertificates)
        {
            certificate.Dispose();
        }
    }
}

public class TlsSecretCertificateLease(CertificateEntry certificateEntry) : IDisposable
{
    private CertificateEntry _certificateEntry = certificateEntry;

    public X509Certificate2 LeafCertificate =>
        (_certificateEntry ?? throw new ObjectDisposedException(nameof(TlsSecretCertificateLease))).LeafCertificate;

    public X509Certificate2Collection IntermediateCertificates =>
        (_certificateEntry ?? throw new ObjectDisposedException(nameof(TlsSecretCertificateLease)))
        .IntermediateCertificates;

    public void Dispose() => Interlocked.Exchange(ref _certificateEntry, null)?.Release();
}
