// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Yarp.Kubernetes.Controller.Certificates.Tests;

public class TlsSecretCertificateStoreTests : IDisposable
{
    private static readonly TimeSpan _gracePeriod = TimeSpan.FromMinutes(10);

    private readonly NamespacedName _secretA = new("default", "secret-a");
    private readonly NamespacedName _secretB = new("default", "secret-b");
    private readonly ManualTimeProvider _timeProvider = new();
    private readonly TlsSecretCertificateStore _store;

    public TlsSecretCertificateStoreTests()
    {
        _store = new TlsSecretCertificateStore(
            NullLogger<TlsSecretCertificateStore>.Instance, _timeProvider, _gracePeriod);
    }

    public void Dispose() => _store.Dispose();

    [Fact]
    public void Constructor_CreatesCleanupTimerWithGracePeriod()
    {
        var gracePeriod = TimeSpan.FromMinutes(3);
        var timeProvider = new ManualTimeProvider();

        using var store = new TlsSecretCertificateStore(
            NullLogger<TlsSecretCertificateStore>.Instance, timeProvider, gracePeriod);

        // The store creates its cleanup timer through the TimeProvider, which captures it.
        var cleanupTimer = timeProvider.Timer;
        Assert.Equal(gracePeriod, cleanupTimer.DueTime);
        Assert.Equal(gracePeriod, cleanupTimer.Period);
    }

    [Fact]
    public void TryAcquire_UnknownSecret_ReturnsFalse()
    {
        Assert.False(_store.TryAcquire(_secretA, out var lease));
        Assert.Null(lease);
    }

    [Fact]
    public void Replace_NullChain_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _store.Replace(_secretA, null));
    }

    [Fact]
    public void Replace_ThenTryAcquire_ReturnsLeaseForChain()
    {
        var chain = CreateChain(intermediateCount: 2);
        _store.Replace(_secretA, chain);

        Assert.True(_store.TryAcquire(_secretA, out var lease));
        using (lease)
        {
            Assert.Same(chain.LeafCertificate, lease.LeafCertificate);
            Assert.Same(chain.IntermediateCertificates, lease.IntermediateCertificates);
        }
    }

    [Fact]
    public void Replace_SecretsAreIndependent()
    {
        var chainA = CreateChain();
        var chainB = CreateChain();
        _store.Replace(_secretA, chainA);
        _store.Replace(_secretB, chainB);

        _store.Remove(_secretA);

        Assert.False(_store.TryAcquire(_secretA, out _));
        Assert.True(_store.TryAcquire(_secretB, out var lease));
        using (lease)
        {
            Assert.Same(chainB.LeafCertificate, lease.LeafCertificate);
        }
    }

    [Fact]
    public void Replace_ExistingSecret_NewLeasesUseNewChain()
    {
        var oldChain = CreateChain();
        var newChain = CreateChain();
        _store.Replace(_secretA, oldChain);
        _store.Replace(_secretA, newChain);

        Assert.True(_store.TryAcquire(_secretA, out var lease));
        using (lease)
        {
            Assert.Same(newChain.LeafCertificate, lease.LeafCertificate);
        }

        Assert.False(IsDisposed(oldChain));
    }

    [Fact]
    public void Replace_OldChainKeptBeforeGracePeriodElapses()
    {
        var oldChain = CreateChain(intermediateCount: 1);
        _store.Replace(_secretA, oldChain);
        _store.Replace(_secretA, CreateChain());

        _timeProvider.Advance(_gracePeriod - TimeSpan.FromSeconds(1));
        _timeProvider.FireTimer();

        Assert.False(IsDisposed(oldChain));
    }

    [Fact]
    public void Replace_OldChainDisposedAfterGracePeriod()
    {
        var oldChain = CreateChain(intermediateCount: 1);
        var newChain = CreateChain();
        _store.Replace(_secretA, oldChain);
        _store.Replace(_secretA, newChain);

        _timeProvider.Advance(_gracePeriod);
        _timeProvider.FireTimer();

        Assert.True(IsDisposed(oldChain));
        Assert.False(IsDisposed(newChain));
    }

    [Fact]
    public void Replace_ActiveLeaseKeepsOldChainAliveUntilReleased()
    {
        var oldChain = CreateChain();
        _store.Replace(_secretA, oldChain);
        Assert.True(_store.TryAcquire(_secretA, out var lease));

        _store.Replace(_secretA, CreateChain());
        _timeProvider.Advance(_gracePeriod);
        _timeProvider.FireTimer();

        Assert.False(IsDisposed(oldChain));
        Assert.Same(oldChain.LeafCertificate, lease.LeafCertificate);

        lease.Dispose();

        Assert.True(IsDisposed(oldChain));
    }

    [Fact]
    public void Replace_LeaseReleasedBeforeGracePeriod_ChainDisposedWhenGracePeriodElapses()
    {
        var oldChain = CreateChain();
        _store.Replace(_secretA, oldChain);
        Assert.True(_store.TryAcquire(_secretA, out var lease));
        _store.Replace(_secretA, CreateChain());

        lease.Dispose();
        Assert.False(IsDisposed(oldChain));

        _timeProvider.Advance(_gracePeriod);
        _timeProvider.FireTimer();
        Assert.True(IsDisposed(oldChain));
    }

    [Fact]
    public void Replace_MultipleRetirements_OnlyThosePastGracePeriodAreDisposed()
    {
        var first = CreateChain();
        var second = CreateChain();
        _store.Replace(_secretA, first);
        _store.Replace(_secretA, second); // retires first at t=0

        _timeProvider.Advance(TimeSpan.FromMinutes(5));
        _store.Replace(_secretA, CreateChain()); // retires second at t=5

        _timeProvider.Advance(TimeSpan.FromMinutes(5));
        _timeProvider.FireTimer();
        Assert.True(IsDisposed(first));
        Assert.False(IsDisposed(second));

        _timeProvider.Advance(TimeSpan.FromMinutes(5));
        _timeProvider.FireTimer();
        Assert.True(IsDisposed(second));
    }

    [Fact]
    public void Remove_UnknownSecret_DoesNothing()
    {
        _store.Remove(_secretA);

        Assert.False(_store.TryAcquire(_secretA, out _));
    }

    [Fact]
    public void Remove_SecretNoLongerAcquirable()
    {
        _store.Replace(_secretA, CreateChain());

        _store.Remove(_secretA);

        Assert.False(_store.TryAcquire(_secretA, out var lease));
        Assert.Null(lease);
    }

    [Fact]
    public void Remove_ChainDisposedOnlyAfterGracePeriod()
    {
        var chain = CreateChain();
        _store.Replace(_secretA, chain);
        _store.Remove(_secretA);

        _timeProvider.FireTimer();
        Assert.False(IsDisposed(chain));

        _timeProvider.Advance(_gracePeriod);
        _timeProvider.FireTimer();
        Assert.True(IsDisposed(chain));
    }

    [Fact]
    public void Remove_ActiveLeaseKeepsChainAliveUntilReleased()
    {
        var chain = CreateChain();
        _store.Replace(_secretA, chain);
        Assert.True(_store.TryAcquire(_secretA, out var lease));
        _store.Remove(_secretA);

        _timeProvider.Advance(_gracePeriod);
        _timeProvider.FireTimer();
        Assert.False(IsDisposed(chain));

        lease.Dispose();
        Assert.True(IsDisposed(chain));
    }

    [Fact]
    public void Remove_ThenReplace_SecretAcquirableAgain()
    {
        _store.Replace(_secretA, CreateChain());
        _store.Remove(_secretA);
        var chain = CreateChain();
        _store.Replace(_secretA, chain);

        Assert.True(_store.TryAcquire(_secretA, out var lease));
        using (lease)
        {
            Assert.Same(chain.LeafCertificate, lease.LeafCertificate);
        }
    }

    [Fact]
    public void Lease_DisposeTwice_ReleasesOnlyOnce()
    {
        var chain = CreateChain();
        _store.Replace(_secretA, chain);
        Assert.True(_store.TryAcquire(_secretA, out var first));
        Assert.True(_store.TryAcquire(_secretA, out var second));
        _store.Remove(_secretA);
        _timeProvider.Advance(_gracePeriod);
        _timeProvider.FireTimer();

        first.Dispose();
        first.Dispose();

        Assert.False(IsDisposed(chain));

        second.Dispose();
        Assert.True(IsDisposed(chain));
    }

    [Fact]
    public void Lease_AccessAfterDispose_Throws()
    {
        _store.Replace(_secretA, CreateChain());
        Assert.True(_store.TryAcquire(_secretA, out var lease));

        lease.Dispose();

        Assert.Throws<ObjectDisposedException>(() => lease.LeafCertificate);
        Assert.Throws<ObjectDisposedException>(() => lease.IntermediateCertificates);
    }

    [Fact]
    public void Dispose_DisposesCurrentAndRetiredChainsWithoutLeases()
    {
        var retired = CreateChain();
        var current = CreateChain();
        _store.Replace(_secretA, retired);
        _store.Replace(_secretA, current);

        _store.Dispose();

        Assert.True(IsDisposed(retired));
        Assert.True(IsDisposed(current));
    }

    [Fact]
    public void Dispose_ActiveLeaseKeepsChainAliveUntilReleased()
    {
        var chain = CreateChain();
        _store.Replace(_secretA, chain);
        Assert.True(_store.TryAcquire(_secretA, out var lease));

        _store.Dispose();
        Assert.False(IsDisposed(chain));
        Assert.Same(chain.LeafCertificate, lease.LeafCertificate);

        lease.Dispose();
        Assert.True(IsDisposed(chain));
    }

    [Fact]
    public void Dispose_DisposesCleanupTimer()
    {
        _store.Dispose();

        Assert.True(_timeProvider.Timer.IsDisposed);
    }

    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        _store.Dispose();
        _store.Dispose();
    }

    [Fact]
    public void Dispose_SubsequentOperationsThrow()
    {
        _store.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _store.TryAcquire(_secretA, out _));
        Assert.Throws<ObjectDisposedException>(() => _store.Replace(_secretA, CreateChain()));
        Assert.Throws<ObjectDisposedException>(() => _store.Remove(_secretA));
    }

    [Fact]
    public void TimerCallback_AfterDispose_DoesNotThrow()
    {
        _store.Dispose();

        _timeProvider.FireTimer();
    }

    [Fact]
    public async Task TryAcquire_ConcurrentWithReplace_AlwaysReturnsUsableLease()
    {
        _store.Replace(_secretA, CreateChain());
        var chains = new List<TlsCertificateChain>();
        for (var i = 0; i < 20; i++)
        {
            chains.Add(CreateChain());
        }

        using var cts = new CancellationTokenSource();
        var reader = Task.Run(() =>
        {
            var acquired = 0;
            do
            {
                Assert.True(_store.TryAcquire(_secretA, out var lease));
                using (lease)
                {
                    Assert.NotEqual(IntPtr.Zero, lease.LeafCertificate.Handle);
                }

                acquired++;
            } while (!cts.IsCancellationRequested);

            return acquired;
        });

        foreach (var chain in chains)
        {
            _store.Replace(_secretA, chain);
            _timeProvider.Advance(_gracePeriod);
            _timeProvider.FireTimer();
        }

        cts.Cancel();
        Assert.True(await reader > 0);
    }

    private static TlsCertificateChain CreateChain(int intermediateCount = 0)
    {
        var intermediates = new X509Certificate2Collection();
        for (var i = 0; i < intermediateCount; i++)
        {
            intermediates.Add(CreateCertificate($"CN=intermediate-{i}"));
        }

        return new TlsCertificateChain(CreateCertificate("CN=leaf"), intermediates);
    }

    private static X509Certificate2 CreateCertificate(string subject)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
    }

    private static bool IsDisposed(TlsCertificateChain chain)
    {
        if (chain.LeafCertificate.Handle != IntPtr.Zero)
        {
            return false;
        }

        foreach (var certificate in chain.IntermediateCertificates)
        {
            if (certificate.Handle != IntPtr.Zero)
            {
                return false;
            }
        }

        return true;
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public ManualTimer Timer { get; private set; }

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan delta) => _utcNow += delta;

        public void FireTimer() => Timer.Callback(Timer.State);

        public override ITimer CreateTimer(TimerCallback callback, object state, TimeSpan dueTime, TimeSpan period)
        {
            Assert.Null(Timer);
            Timer = new ManualTimer(callback, state, dueTime, period);
            return Timer;
        }
    }

    private sealed class ManualTimer(TimerCallback callback, object state, TimeSpan dueTime, TimeSpan period) : ITimer
    {
        public TimerCallback Callback { get; } = callback;
        public object State { get; } = state;
        public TimeSpan DueTime { get; private set; } = dueTime;
        public TimeSpan Period { get; private set; } = period;
        public bool IsDisposed { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            DueTime = dueTime;
            Period = period;
            return true;
        }

        public void Dispose() => IsDisposed = true;

        public ValueTask DisposeAsync()
        {
            IsDisposed = true;
            return default;
        }
    }
}
