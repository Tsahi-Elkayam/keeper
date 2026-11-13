namespace Keeper.Runners.Cim;

/// <summary>How a host took a first contact over one transport.</summary>
public enum Reach
{
    /// <summary>It answered.</summary>
    Answered,

    /// <summary>It answered and said no - access denied, a bad ticket, a logon failure. Another transport would only repeat the failed logon.</summary>
    Refused,

    /// <summary>Nothing answered: no listener, a firewall, a timeout. Another transport may.</summary>
    Unreachable,
}

public sealed record ChainResult(string? Transport, string? FirstReason, IReadOnlyList<string> Tried);

/// <summary>
/// Walks a transport chain until one gets through. Pure logic, no Windows API: the caller supplies the contact test.
/// A refusal ends the walk on that transport - the query then reports the refusal - because trying the next
/// transport with the same credential would count a second failed logon towards a lockout.
/// </summary>
public static class TransportChain
{
    public static ChainResult Resolve(IReadOnlyList<string> chain, Func<string, (Reach Reach, string? Why)> contact)
    {
        if (chain.Count == 0)
            throw new ArgumentException("A transport chain needs at least one transport.", nameof(chain));

        var tried = new List<string>();
        string? firstReason = null;
        foreach (var transport in chain)
        {
            tried.Add(transport);
            var (reach, why) = contact(transport);
            if (reach is Reach.Answered or Reach.Refused)
                return new ChainResult(transport, null, tried);
            firstReason ??= why;
        }
        return new ChainResult(null, firstReason, tried);
    }
}
