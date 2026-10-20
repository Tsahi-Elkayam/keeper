namespace Keeper.Core;

/// <summary>What is wrong - the three questions a review answers.</summary>
public enum FindingKind
{
    /// <summary>Does not work, or stops working by its deadline.</summary>
    Broken,

    /// <summary>Exists, but is configured against a standard or best practice.</summary>
    Misconfigured,

    /// <summary>Should exist or should have been done, and isn't: missing configuration, an overdue duty.</summary>
    Missing,
}

/// <summary>Where a finding stands. Open, Unverified and Blocked are active.</summary>
public enum FindingStatus
{
    Open,
    Unverified,
    Blocked,
    Ok,
    Info,
    Resolved,
    Disabled,
    Exception,
}

/// <summary>
/// How a finding got to its status. A finding resolves only when its check passes again;
/// a closed ticket only makes it ClaimedFixed.
/// </summary>
public enum FindingLifecycle
{
    New,
    Open,
    Reopened,
    Resolved,
    Disabled,
    ClaimedFixed,
    Stale,
    NotApplicable,
}
