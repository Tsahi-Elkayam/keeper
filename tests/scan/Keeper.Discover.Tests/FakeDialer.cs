using System.Collections.Concurrent;
using System.Net;

namespace Keeper.Discover.Tests;

/// <summary>
/// Scripted in-memory dialer for multi-host and protocol probe tests without touching the OS network stack.
/// Records every attempted TCP/UDP dial and tracks bytes written by probes to verify send-nothing rules.
/// </summary>
public sealed class FakeDialer : IDialer
{
    public sealed class MemoryTcpSession(byte[] serverToClient, List<byte> clientToServer) : ITcpSession
    {
        public Stream Stream { get; } = new DuplexMemoryStream(serverToClient, clientToServer);

        public void Dispose() => Stream.Dispose();

        public ValueTask DisposeAsync() => Stream.DisposeAsync();
    }

    private sealed class DuplexMemoryStream(byte[] readable, List<byte> written) : Stream
    {
        private int _readPos;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => readable.Length;
        public override long Position { get => _readPos; set => throw new NotSupportedException(); }

        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var avail = readable.Length - _readPos;
            if (avail <= 0)
                return 0;
            var toCopy = Math.Min(count, avail);
            Array.Copy(readable, _readPos, buffer, offset, toCopy);
            _readPos += toCopy;
            return toCopy;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.FromResult(Read(buffer, offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var avail = readable.Length - _readPos;
            if (avail <= 0)
                return ValueTask.FromResult(0);
            var toCopy = Math.Min(buffer.Length, avail);
            readable.AsSpan(_readPos, toCopy).CopyTo(buffer.Span);
            _readPos += toCopy;
            return ValueTask.FromResult(toCopy);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            lock (written)
                written.AddRange(buffer.AsSpan(offset, count).ToArray());
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            lock (written)
                written.AddRange(buffer.ToArray());
            return ValueTask.CompletedTask;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private readonly ConcurrentDictionary<(string Ip, int Port), Func<(string State, int RttMs, byte[] ServerBytes, List<byte> ClientWritten)>> _tcpHandlers = new();
    private readonly ConcurrentDictionary<(string Ip, int Port), Func<byte[], UdpDialResult>> _udpHandlers = new();
    private readonly ConcurrentQueue<(string Transport, string Ip, int Port)> _log = new();

    public IReadOnlyCollection<(string Transport, string Ip, int Port)> DialLog => _log.ToList();

    public List<byte> MapTcpOpen(string ip, int port, byte[]? serverBytes = null, int rttMs = 2)
    {
        var written = new List<byte>();
        var bytes = serverBytes ?? [];
        _tcpHandlers[(ip, port)] = () => (DialStates.Open, rttMs, bytes, written);
        return written;
    }

    public void MapTcpState(string ip, int port, string state, int rttMs = 2) =>
        _tcpHandlers[(ip, port)] = () => (state, rttMs, [], []);

    public void MapUdp(string ip, int port, Func<byte[], UdpDialResult> handler) =>
        _udpHandlers[(ip, port)] = handler;

    public Task<TcpDialResult> ConnectTcpAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var ip = Addresses.Canonical(address);
        _log.Enqueue(("tcp", ip, port));
        if (!_tcpHandlers.TryGetValue((ip, port), out var fn))
            return Task.FromResult(new TcpDialResult(DialStates.Filtered, null, null, "no handler"));

        var (state, rtt, serverBytes, clientWritten) = fn();
        if (state != DialStates.Open)
            return Task.FromResult(new TcpDialResult(state, state == DialStates.Closed ? rtt : null));

        return Task.FromResult(new TcpDialResult(DialStates.Open, rtt, new MemoryTcpSession(serverBytes, clientWritten)));
    }

    public Task<UdpDialResult> ExchangeUdpAsync(IPAddress address, int port, ReadOnlyMemory<byte> request, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var ip = Addresses.Canonical(address);
        _log.Enqueue(("udp", ip, port));
        if (!_udpHandlers.TryGetValue((ip, port), out var fn))
            return Task.FromResult(new UdpDialResult(DialStates.Filtered, null, null, "no handler"));

        return Task.FromResult(fn(request.ToArray()));
    }
}
