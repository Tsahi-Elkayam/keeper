using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Keeper.Discover;

public static class DialStates
{
    public const string Open = "open";
    public const string Closed = "closed";
    public const string Filtered = "filtered";
    public const string Unreachable = "unreachable";
    public const string RefusedByGate = "refused-by-gate";
}

public interface ITcpSession : IAsyncDisposable, IDisposable
{
    Stream Stream { get; }
}

public sealed record TcpDialResult(string State, int? RttMs, ITcpSession? Session = null, string? Reason = null);

public sealed record UdpDialResult(string State, int? RttMs, byte[]? Payload = null, string? Reason = null);

/// <summary>
/// The lowest-level network dialer. Only <see cref="SocketDialer"/> opens real OS sockets;
/// everything in <c>Keeper.Discover</c> goes through <see cref="ProbeGate"/> over an <see cref="IDialer"/>.
/// </summary>
public interface IDialer
{
    Task<TcpDialResult> ConnectTcpAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken);

    Task<UdpDialResult> ExchangeUdpAsync(IPAddress address, int port, ReadOnlyMemory<byte> request, TimeSpan timeout, CancellationToken cancellationToken);
}

public sealed class SocketDialer : IDialer
{
    private sealed class SocketTcpSession(Socket socket, NetworkStream stream) : ITcpSession
    {
        public Stream Stream => stream;

        public void Dispose()
        {
            stream.Dispose();
            socket.Dispose();
        }

        public async ValueTask DisposeAsync()
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            socket.Dispose();
        }
    }

    public async Task<TcpDialResult> ConnectTcpAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cts.Token).ConfigureAwait(false);
            sw.Stop();
            var rtt = Math.Max(0, (int)sw.ElapsedMilliseconds);
            var stream = new NetworkStream(socket, ownsSocket: true);
            return new TcpDialResult(DialStates.Open, rtt, new SocketTcpSession(socket, stream));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            socket.Dispose();
            return new TcpDialResult(DialStates.Filtered, null, null, "connection timed out");
        }
        catch (SocketException ex)
        {
            sw.Stop();
            socket.Dispose();
            var rtt = Math.Max(0, (int)sw.ElapsedMilliseconds);
            return ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => new TcpDialResult(DialStates.Closed, rtt, null, "connection refused"),
                SocketError.TimedOut => new TcpDialResult(DialStates.Filtered, null, null, "connection timed out"),
                SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.HostDown or SocketError.AddressNotAvailable
                    => new TcpDialResult(DialStates.Unreachable, null, null, ex.SocketErrorCode.ToString()),
                _ => new TcpDialResult(DialStates.Filtered, null, null, ex.SocketErrorCode.ToString()),
            };
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public async Task<UdpDialResult> ExchangeUdpAsync(IPAddress address, int port, ReadOnlyMemory<byte> request, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        try
        {
            var endpoint = new IPEndPoint(address, port);
            await socket.ConnectAsync(endpoint, cts.Token).ConfigureAwait(false);
            await socket.SendAsync(request, SocketFlags.None, cts.Token).ConfigureAwait(false);
            var buffer = new byte[8192];
            var read = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return new UdpDialResult(DialStates.Open, Math.Max(0, (int)sw.ElapsedMilliseconds), buffer.AsSpan(0, read).ToArray());
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new UdpDialResult(DialStates.Filtered, null, null, "udp receive timed out");
        }
        catch (SocketException ex)
        {
            sw.Stop();
            return ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused or SocketError.ConnectionReset
                    => new UdpDialResult(DialStates.Closed, Math.Max(0, (int)sw.ElapsedMilliseconds), null, "icmp port unreachable"),
                _ => new UdpDialResult(DialStates.Filtered, null, null, ex.SocketErrorCode.ToString()),
            };
        }
    }
}
