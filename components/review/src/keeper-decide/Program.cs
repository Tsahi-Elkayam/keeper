using Keeper.Common;
using Keeper.Review.Cli;

// keeper-decide: the decisions a person makes about findings and rules. Each one is queued with its
// reason, so every decision is on record with who made it and why.
return RequestCli.Run("keeper-decide", args, ["remove"], Decide, Usage);

static int Decide(RequestCli r)
{
    var cli = r.Cli;
    switch (cli.At(0))
    {
        case "snooze":
        {
            var finding = Find(r, 1);
            var until = RequestCli.Date(cli.Require("until"), "--until");
            return r.Submit("review.triage", new { findingKey = finding.Key, decision = "snooze", until },
                $"{finding.Title} snoozed until {until}.");
        }
        case "delegate":
        {
            var finding = Find(r, 1);
            var owner = cli.Require("to");
            return r.Submit("review.triage", new { findingKey = finding.Key, decision = "delegate", owner },
                $"{finding.Title} handed to {owner}.");
        }
        case "clear":
        {
            var finding = Find(r, 1);
            return r.Submit("review.triage", new { findingKey = finding.Key, decision = "clear" },
                $"{finding.Title}: snooze or hand-off cleared.");
        }
        case "accept":
        {
            // An exception for this one entity: the rule keeps running on everything else.
            var finding = Find(r, 1);
            var until = Until(cli);
            return r.Submit("review.override", new { op = "add", checkId = finding.CheckId, decision = "exception", entity = finding.Target, until },
                $"{finding.CheckId} accepted for {finding.Target}{Ends(until)}.");
        }
        case "disable":
        {
            var check = r.Positional(1, "the rule id (or a prefix ending in *)");
            var until = Until(cli);
            return r.Submit("review.override", new { op = "add", checkId = check, decision = "disable", until }, $"{check} disabled{Ends(until)}.");
        }
        case "threshold":
        {
            var check = r.Positional(1, "the rule id");
            var value = r.Positional(2, "the threshold value");
            var until = Until(cli);
            return r.Submit("review.override", new { op = "add", checkId = check, decision = "threshold", value, until },
                $"{check} threshold set to {value}{Ends(until)}.");
        }
        case "undo":
        {
            var id = r.Positional(1, "the override id (OVR-0001; 'keeper decisions' lists them)");
            return r.Submit("review.override", new { op = "remove", overrideId = id }, $"{id} removed.");
        }
        case "setting":
        {
            var key = r.Positional(1, "the setting key, e.g. threshold.ad.stale-user-days");
            if (cli.Has("remove"))
                return r.Submit("review.setting", new { key, remove = true }, $"{key} removed.");
            var value = r.Positional(2, "the value");
            return r.Submit("review.setting", new { key, value }, $"{key} = {value}.");
        }
        case "attest":
        {
            var obligation = r.Positional(1, "the obligation, e.g. backup.restore-test");
            var payload = new
            {
                obligation,
                target = cli.Get("target") ?? "-",
                state = cli.Get("state") ?? "yes",
                evidence = cli.Require("evidence"),
                doneOn = cli.Get("done-on") is { } d ? RequestCli.Date(d, "--done-on") : Iso.Date(DateTimeOffset.UtcNow),
                expiresOn = cli.Get("expires-on") is { } e ? RequestCli.Date(e, "--expires-on") : null,
            };
            return r.Submit("review.attestation", payload, $"{obligation} attested ({payload.state}).");
        }
        default:
            return Usage();
    }
}

static string? Until(CliArgs cli) => cli.Get("until") is { } until ? RequestCli.Date(until, "--until") : null;

static string Ends(string? until) => until is null ? "" : $" until {until}";

static FindingRef Find(RequestCli r, int index)
{
    using var connection = r.Read();
    return RequestCli.Finding(connection, r.Positional(index, "the finding key"));
}

static int Usage(bool asked = false) =>
    CliUsage.Print("""
        keeper-decide - decisions about findings and rules; each needs --reason and is kept on record

          keeper decide snooze <key> --until <yyyy-MM-dd|2w>      out of today's list until then
          keeper decide delegate <key> --to <owner>               waiting on someone else
          keeper decide clear <key>                               undo a snooze or hand-off
          keeper decide accept <key> [--until <date|26w>]         accept this one entity as it is (an exception)
          keeper decide disable <rule-id> [--until <date|4w>]     stop reporting a rule (prefix* allowed)
          keeper decide threshold <rule-id> <value> [--until ..]  this rule's threshold, for this tenant
                                                                  --until: the last day it holds; then the finding is back
          keeper decide undo <OVR-0001>                           remove an exception, disable or threshold
          keeper decide setting <key> <value> | --remove          e.g. threshold.ad.stale-user-days 120
          keeper decide attest <obligation> --evidence "<what>" [--state yes|no|na] [--target t]
                               [--done-on <date>] [--expires-on <date|52w>]

          <key> is a finding key or its first 6+ characters. --now applies it straight away.
        """, asked);
