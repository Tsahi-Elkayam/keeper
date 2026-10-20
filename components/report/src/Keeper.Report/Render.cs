using System.Globalization;
using System.Net;
using System.Text;

namespace Keeper.Report;

/// <summary>
/// A report as sections of lines, so one model renders as text, Markdown or HTML. Everything that came
/// from a scanned system is untrusted: HTML output encodes all of it, Markdown escapes what would format.
/// </summary>
public sealed record Section(string Title, IReadOnlyList<string> Lines, string? Empty = null);

public sealed record Document(string Title, string Subtitle, IReadOnlyList<Section> Sections);

public static class Render
{
    public static string Text(Document document)
    {
        var output = new StringBuilder();
        output.AppendLine(document.Title).AppendLine(document.Subtitle).AppendLine();
        foreach (var section in document.Sections)
        {
            output.AppendLine(section.Title).AppendLine(new string('-', section.Title.Length));
            if (section.Lines.Count == 0 && section.Empty is not null)
                output.AppendLine("  " + section.Empty);
            foreach (var line in section.Lines)
                output.AppendLine("  " + line);
            output.AppendLine();
        }
        return output.ToString();
    }

    public static string Markdown(Document document)
    {
        var output = new StringBuilder();
        output.AppendLine($"# {Md(document.Title)}").AppendLine().AppendLine($"_{Md(document.Subtitle)}_").AppendLine();
        foreach (var section in document.Sections)
        {
            output.AppendLine($"## {Md(section.Title)}").AppendLine();
            if (section.Lines.Count == 0 && section.Empty is not null)
                output.AppendLine(Md(section.Empty));
            foreach (var line in section.Lines)
                output.AppendLine($"- {Md(line)}");
            output.AppendLine();
        }
        return output.ToString();
    }

    public static string Html(Document document)
    {
        static string E(string text) => WebUtility.HtmlEncode(text);
        var output = new StringBuilder();
        output.Append(CultureInfo.InvariantCulture, $$"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{{E(document.Title)}}</title>
            <style>
              :root { color-scheme: light dark; --fg: #1d1d1f; --bg: #fff; --muted: #666; --line: #e5e5e5; }
              @media (prefers-color-scheme: dark) { :root { --fg: #eee; --bg: #161616; --muted: #aaa; --line: #333; } }
              body { font: 15px/1.5 system-ui, sans-serif; color: var(--fg); background: var(--bg); max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
              h1 { margin-bottom: .2rem; } .sub { color: var(--muted); margin-top: 0; }
              h2 { border-bottom: 1px solid var(--line); padding-bottom: .2rem; margin-top: 2rem; }
              li { margin: .35rem 0; } .empty { color: var(--muted); }
            </style></head><body>
            <h1>{{E(document.Title)}}</h1><p class="sub">{{E(document.Subtitle)}}</p>
            """);
        foreach (var section in document.Sections)
        {
            output.Append(CultureInfo.InvariantCulture, $"<h2>{E(section.Title)}</h2>");
            if (section.Lines.Count == 0 && section.Empty is not null)
                output.Append(CultureInfo.InvariantCulture, $"<p class=\"empty\">{E(section.Empty)}</p>");
            if (section.Lines.Count > 0)
            {
                output.Append("<ul>");
                foreach (var line in section.Lines)
                    output.Append(CultureInfo.InvariantCulture, $"<li>{E(line)}</li>");
                output.Append("</ul>");
            }
        }
        output.Append("</body></html>");
        return output.ToString();
    }

    public static string As(Document document, string format) => format switch
    {
        "markdown" or "md" => Markdown(document),
        "html" => Html(document),
        "text" => Text(document),
        _ => throw new ArgumentException("--format must be text, markdown or html."),
    };

    private static string Md(string text)
    {
        var output = new StringBuilder(text.Length);
        foreach (var c in text.ReplaceLineEndings(" "))
        {
            if (c is '\\' or '`' or '*' or '_' or '[' or ']' or '<' or '>' or '#' or '|')
                output.Append('\\');
            output.Append(c);
        }
        return output.ToString();
    }
}

public static class TodayDocument
{
    public static Document From(TodayReport report)
    {
        var minutes = report.Today.Sum(t => t.Minutes);
        var findings = report.Today.Sum(t => t.Targets);
        var today = report.Today.Select(t =>
        {
            var due = t.Deadline is null ? "" : t.DaysLeft switch
            {
                < 0 => $" - OVERDUE since {t.Deadline}",
                0 => " - due today",
                _ => $" - due {t.Deadline}",
            };
            var next = string.IsNullOrWhiteSpace(t.Fix) ? "" : $" Next: {Short(t.Fix!, 160)}";
            var where = t.Targets <= 1
                ? $"{t.SystemId} / {t.Target}"
                : $"{t.Targets} targets{(t.Systems > 1 ? $" on {t.Systems} systems" : $" on {t.SystemId}")}, e.g. {string.Join(", ", t.Examples ?? [])}";
            return $"{t.Position}. [{t.Severity}] {t.Title} - {where}{due}. Why now: {string.Join(", ", t.Reasons)}. (~{t.Minutes} min, key {t.FindingKey[..8]}){next}";
        }).ToList();

        return new Document(
            "What to do today",
            report.RankedAt is null
                ? "No ranking yet: run 'keeper run' (or 'keeper rank')."
                : $"Ranked {report.RankedAt}. {report.Today.Count} tasks covering {findings} findings, about {minutes} of {report.BudgetMinutes} minutes.",
            [
                new Section("Today", today, "Nothing ranked for today."),
                new Section("Waiting on others",
                    report.Waiting.Select(w => $"{w.Owner}: [{w.Severity}] {w.Title} ({w.SystemId}) - {w.DaysWaiting} days").ToList(),
                    "Nothing handed off."),
                new Section("Due soon",
                    report.DueSoon.Select(d => $"{d.What}: {d.Title} - {(d.DaysLeft < 0 ? $"overdue since {d.DueOn}" : $"{d.DueOn} ({d.DaysLeft} days)")}").ToList(),
                    "Nothing falls due in the next days."),
                new Section($"New since yesterday ({report.NewSinceYesterday})", report.NewTitles.ToList(), "Nothing new."),
                new Section("Blind spots",
                    [.. report.StaleScans.Select(s => "Not scanned recently: " + s),
                     .. report.BlindSpots.Select(b => $"{b.System} via {b.Instance}: {b.Item} {b.State}{(b.Why is null ? "" : " - " + Short(b.Why, 200))}"),
                     .. report.NeverScanned.Count == 0 ? Array.Empty<string>()
                         : [$"Never scanned - none of these checks has run (add an integration, or accept KEEPER-SYSTEM-NEVER-SCANNED): {string.Join(", ", report.NeverScanned)}"]],
                    "Every source answered in its newest scan."),
            ]);
    }

    private static string Short(string text, int max) => text.Length <= max ? text : text[..max] + "...";
}
