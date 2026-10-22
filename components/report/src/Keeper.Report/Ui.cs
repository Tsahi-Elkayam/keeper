using System.Text.Json.Nodes;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// keeper ui: the whole picture as one interactive page - no server, no port, nothing fetched from anywhere. The
/// store's answers are embedded as JSON and drawn by the page's own script. Everything that came from a scanned
/// system is written as text (textContent), never as markup, and the JSON escapes '&lt;' so it cannot close its
/// script element.
/// </summary>
public static class Ui
{
    public static string Build(SqliteConnection connection, DateTimeOffset now, string? tenant)
    {
        var gpoNames = Reports.GpoNames(connection);
        string? Named(object? value) => value is string text ? Reports.Named(text, gpoNames) : null;

        var systems = Rows(connection,
            """
            SELECT st.system, st.instance, COUNT(*) AS checks,
                   SUM(st.standing = 'correct') AS correct, SUM(st.standing = 'should-configure') AS should,
                   SUM(st.standing = 'broken') AS broken, SUM(st.standing = 'not-checked') AS unchecked,
                   (SELECT COUNT(*) FROM rule r WHERE r.system = st.system) - COUNT(*) AS norun,
                   MAX(st.tested_at) AS scanned
            FROM rule_standing st GROUP BY st.system, st.instance ORDER BY st.system, st.instance;
            """);

        // Open findings, one entry per check, with every object it was found on.
        var objects = new Dictionary<string, JsonArray>(StringComparer.Ordinal);
        foreach (var r in Sql.Rows(connection,
                     "SELECT check_id, COALESCE(entity_name, target) AS name, evidence FROM active_finding ORDER BY check_id, name;"))
        {
            var id = (string)r["check_id"]!;
            if (!objects.TryGetValue(id, out var list))
                objects[id] = list = [];
            list.Add(new JsonArray(Named(r["name"]), Named(r["evidence"])));
        }
        var checks = new JsonArray();
        foreach (var r in Sql.Rows(connection,
                     """
                     SELECT check_id, MIN(severity_rank) AS rank, severity, kind, title, why, fix, refs, system, category, security,
                            COUNT(*) AS n, MIN(first_seen) AS first_seen
                     FROM active_finding GROUP BY check_id ORDER BY rank, n DESC, title;
                     """))
        {
            var id = (string)r["check_id"]!;
            checks.Add(new JsonObject
            {
                ["id"] = id, ["severity"] = (string?)r["severity"], ["kind"] = (string?)r["kind"], ["title"] = (string?)r["title"],
                ["why"] = (string?)r["why"], ["fix"] = (string?)r["fix"], ["system"] = (string?)r["system"], ["category"] = (string?)r["category"],
                ["security"] = r["security"] is 1L, ["count"] = (long)r["n"]!, ["firstSeen"] = (string?)r["first_seen"],
                ["refs"] = r["refs"] is string refs && JsonNode.Parse(refs) is JsonArray parsed ? parsed : new JsonArray(),
                ["objects"] = objects.TryGetValue(id, out var list) ? list : new JsonArray(),
            });
        }

        var data = new JsonObject
        {
            ["generated"] = now.ToString("yyyy-MM-dd HH:mm 'UTC'", System.Globalization.CultureInfo.InvariantCulture),
            ["tenant"] = tenant,
            ["systems"] = systems,
            ["checks"] = checks,
            ["passed"] = Rows(connection,
                """
                SELECT st.system, st.rule_id AS id, st.title, st.severity, st.passed, st.threshold_override AS override
                FROM rule_standing st JOIN severity s ON s.code = st.severity
                WHERE st.standing = 'correct' ORDER BY st.system, s.rank, st.rule_id;
                """),
            ["unchecked"] = Rows(connection,
                "SELECT system, rule_id AS id, title, severity, why_not_correct AS why FROM rule_standing WHERE standing = 'not-checked' ORDER BY system, rule_id;"),
            ["coverage"] = Rows(connection,
                """
                SELECT r.system, c.state, c.reason, COUNT(*) AS n FROM coverage c JOIN latest_run r ON r.run_id = c.run_id
                WHERE c.scope IN ('query', 'target') AND c.state IN ('failed', 'partial') GROUP BY r.system, c.reason ORDER BY r.system;
                """),
            ["neverScanned"] = Rows(connection,
                "SELECT system, COUNT(*) AS rules FROM rule WHERE system NOT IN (SELECT DISTINCT system FROM rule_standing) GROUP BY system ORDER BY rules DESC;"),
        };

        // The default encoder escapes < > & ' " and every non-ASCII character, so the JSON is inert inside the page.
        return Page.Replace("/*KEEPER-DATA*/", data.ToJsonString(), StringComparison.Ordinal);
    }

    private static JsonArray Rows(SqliteConnection connection, string sql)
    {
        var array = new JsonArray();
        foreach (var row in Sql.Rows(connection, sql))
        {
            var obj = new JsonObject();
            foreach (var (key, value) in row)
                obj[key] = value switch { null => null, long n => n, double d => d, string s => s, _ => value.ToString() };
            array.Add(obj);
        }
        return array;
    }

    private const string Page = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>Keeper</title>
<style>
:root { color-scheme: light;
  --page:#f9f9f7; --surface:#fcfcfb; --raise:#ffffff; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781; --grid:#e1e0d9; --axis:#c3c2b7;
  --border:rgba(11,11,11,.10); --accent:#2a78d6; --accent-wash:rgba(42,120,214,.10);
  --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b; --unchecked:#898781; --norun:#d9d8d1;
  --shadow:0 1px 2px rgba(0,0,0,.04), 0 4px 16px rgba(0,0,0,.05); }
@media (prefers-color-scheme: dark) { :root:where(:not([data-theme="light"])) { color-scheme: dark;
  --page:#0d0d0d; --surface:#1a1a19; --raise:#202020; --ink:#f0efec; --ink2:#c3c2b7; --muted:#898781; --grid:#2c2c2a; --axis:#383835;
  --border:rgba(255,255,255,.10); --accent:#3987e5; --accent-wash:rgba(57,135,229,.16); --norun:#383835; --shadow:none; } }
:root[data-theme="dark"] { color-scheme: dark;
  --page:#0d0d0d; --surface:#1a1a19; --raise:#202020; --ink:#f0efec; --ink2:#c3c2b7; --muted:#898781; --grid:#2c2c2a; --axis:#383835;
  --border:rgba(255,255,255,.10); --accent:#3987e5; --accent-wash:rgba(57,135,229,.16); --norun:#383835; --shadow:none; }
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--page); color: var(--ink); font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
button, input, select { font: inherit; color: inherit; }
a { color: var(--accent); }
header { position: sticky; top: 0; z-index: 5; background: color-mix(in srgb, var(--page) 88%, transparent); backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border); }
.bar { max-width: 1280px; margin: 0 auto; padding: 10px 24px; display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; letter-spacing: -.01em; }
.brand .mark { width: 26px; height: 26px; border-radius: 7px; background: linear-gradient(135deg, var(--accent), #6250d6); display: grid; place-items: center; color: #fff; font-size: 14px; }
.brand small { font-weight: 400; color: var(--muted); font-size: 12px; }
nav { display: flex; gap: 4px; }
nav button { border: 0; background: none; padding: 6px 12px; border-radius: 8px; cursor: pointer; color: var(--ink2); }
nav button[aria-current="page"] { background: var(--accent-wash); color: var(--accent); font-weight: 600; }
nav button:hover { background: var(--accent-wash); }
.spacer { flex: 1; }
.search { position: relative; }
.search input { width: 280px; max-width: 60vw; padding: 7px 10px 7px 30px; border: 1px solid var(--border); border-radius: 9px; background: var(--surface); }
.search::before { content: "\2315"; position: absolute; left: 10px; top: 6px; color: var(--muted); }
.icon-btn { border: 1px solid var(--border); background: var(--surface); border-radius: 9px; padding: 6px 10px; cursor: pointer; }
main { max-width: 1280px; margin: 0 auto; padding: 24px; }
h1 { font-size: 26px; letter-spacing: -.02em; margin: 4px 0 6px; } h2 { font-size: 15px; margin: 0 0 12px; }
.lede { color: var(--ink2); font-size: 15px; margin: 0 0 20px; max-width: 900px; }
.grid { display: grid; gap: 16px; }
.tiles { grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); margin-bottom: 16px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px; box-shadow: var(--shadow); }
.tile { cursor: pointer; transition: transform .12s ease, border-color .12s ease; position: relative; overflow: hidden; }
.tile:hover, .tile:focus-visible { transform: translateY(-2px); border-color: var(--accent); outline: none; }
.tile .label { display: flex; align-items: center; gap: 8px; color: var(--ink2); font-weight: 600; }
.tile .value { font-size: 40px; font-weight: 700; letter-spacing: -.03em; line-height: 1.1; margin-top: 6px; }
.tile .note { color: var(--muted); font-size: 12px; }
.tile .stripe { position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
.dot { width: 18px; height: 18px; border-radius: 50%; display: inline-grid; place-items: center; color: #fff; font-size: 11px; font-weight: 700; flex: none; }
.two { grid-template-columns: 1.15fr .85fr; } @media (max-width: 900px) { .two { grid-template-columns: 1fr; } }
.sys { padding: 14px 0; border-top: 1px solid var(--grid); cursor: pointer; } .sys:first-of-type { border-top: 0; }
.sys:hover .sysname { color: var(--accent); }
.sysrow { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 8px; }
.sysname { font-weight: 600; } .meta { color: var(--muted); font-size: 12px; }
.stack { display: flex; gap: 2px; height: 14px; border-radius: 4px; overflow: hidden; background: var(--surface); }
.stack span { display: block; height: 100%; min-width: 2px; }
.stack span:first-child { border-radius: 4px 0 0 4px; } .stack span:last-child { border-radius: 0 4px 4px 0; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 8px; font-size: 12px; color: var(--ink2); }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }
.legend b { color: var(--ink); font-weight: 600; margin-right: 3px; }
.row { display: flex; align-items: center; gap: 10px; padding: 9px 10px; border-radius: 10px; cursor: pointer; }
.row:hover, .row:focus-visible { background: var(--accent-wash); outline: none; }
.row .t { flex: 1; min-width: 0; } .row .t div:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pill { font-size: 12px; font-weight: 600; padding: 1px 8px; border-radius: 99px; background: var(--grid); color: var(--ink); white-space: nowrap; font-variant-numeric: tabular-nums; }
.sev { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; color: var(--ink2); white-space: nowrap; }
.sev::before { content: ""; width: 8px; height: 8px; border-radius: 2px; background: var(--c); }
.hbar { display: grid; grid-template-columns: 92px 1fr auto; gap: 10px; align-items: center; margin: 8px 0; font-size: 13px; }
.hbar .track { height: 12px; background: var(--grid); border-radius: 4px; overflow: hidden; }
.hbar .fill { height: 100%; border-radius: 0 4px 4px 0; }
.hbar .num { color: var(--ink2); font-variant-numeric: tabular-nums; white-space: nowrap; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { border: 1px solid var(--border); background: var(--surface); padding: 4px 10px; border-radius: 99px; cursor: pointer; font-size: 12px; }
.chip[aria-pressed="true"] { background: var(--accent-wash); border-color: var(--accent); color: var(--accent); font-weight: 600; }
.filters { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
.split { display: grid; grid-template-columns: minmax(320px, 440px) 1fr; gap: 16px; align-items: start; }
@media (max-width: 900px) { .split { grid-template-columns: 1fr; } }
.list { max-height: calc(100vh - 230px); overflow: auto; padding: 6px; }
.list .row[aria-selected="true"] { background: var(--accent-wash); box-shadow: inset 3px 0 0 var(--accent); }
.detail { position: sticky; top: 76px; max-height: calc(100vh - 100px); overflow: auto; }
.detail h3 { font-size: 20px; letter-spacing: -.01em; margin: 8px 0 10px; }
.kv { display: flex; flex-wrap: wrap; gap: 6px 14px; color: var(--muted); font-size: 12px; margin-bottom: 12px; }
.block { margin: 14px 0; } .block .h { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-bottom: 4px; }
.fix { border-left: 3px solid var(--good); padding: 8px 12px; background: color-mix(in srgb, var(--good) 8%, transparent); border-radius: 0 8px 8px 0; }
.objs { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.objs .tools { display: flex; gap: 8px; padding: 8px; border-bottom: 1px solid var(--border); background: var(--raise); }
.objs .tools input { flex: 1; padding: 5px 8px; border: 1px solid var(--border); border-radius: 7px; background: var(--surface); }
.obj { padding: 7px 12px; border-top: 1px solid var(--grid); font-size: 13px; } .obj:first-child { border-top: 0; }
.obj b { font-weight: 600; } .obj span { color: var(--ink2); }
.empty { color: var(--muted); padding: 24px; text-align: center; }
.ok { display: flex; gap: 10px; align-items: flex-start; padding: 8px 4px; border-top: 1px solid var(--grid); }
.ok:first-child { border-top: 0; }
.group { margin-bottom: 18px; } .group > .h { font-weight: 700; margin: 0 0 6px; display: flex; gap: 8px; align-items: center; }
#tip { position: fixed; pointer-events: none; z-index: 20; background: var(--raise); border: 1px solid var(--border); border-radius: 8px;
  padding: 6px 10px; font-size: 12px; box-shadow: 0 4px 16px rgba(0,0,0,.18); display: none; }
.kbd { font-size: 11px; border: 1px solid var(--border); border-bottom-width: 2px; border-radius: 5px; padding: 0 5px; color: var(--muted); }
table.data { width: 100%; border-collapse: collapse; font-size: 13px; } table.data th, table.data td { text-align: left; padding: 6px 8px; border-top: 1px solid var(--grid); }
table.data th { color: var(--muted); font-weight: 600; } table.data td.n { text-align: right; font-variant-numeric: tabular-nums; }
details summary { cursor: pointer; color: var(--muted); font-size: 12px; margin-top: 10px; }
.foot { color: var(--muted); font-size: 12px; text-align: center; padding: 24px 0 8px; }
</style></head>
<body>
<header><div class="bar">
  <div class="brand"><div class="mark" aria-hidden="true">K</div><div>Keeper <small id="sub"></small></div></div>
  <nav id="nav"></nav><div class="spacer"></div>
  <label class="search"><input id="q" type="search" placeholder="Search everything" aria-label="Search"></label>
  <button class="icon-btn" id="theme" title="Light / dark">&#9681;</button>
</div></header>
<main id="main"></main>
<div id="tip" role="tooltip"></div>
<script type="application/json" id="keeper-data">/*KEEPER-DATA*/</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("keeper-data").textContent);
const SEV = { critical: "var(--critical)", high: "var(--serious)", medium: "var(--warning)", low: "var(--accent)", info: "var(--muted)" };
const SEVORDER = ["critical", "high", "medium", "low", "info"];
const ST = [
  { key: "correct", label: "Correct", icon: "✓", color: "var(--good)", note: "configured as it should be" },
  { key: "should", label: "Should configure", icon: "!", color: "var(--warning)", note: "missing or against best practice" },
  { key: "broken", label: "Broken", icon: "✕", color: "var(--critical)", note: "configured but not working" },
  { key: "unchecked", label: "Couldn't check", icon: "?", color: "var(--unchecked)", note: "data could not be fully read" },
  { key: "norun", label: "No result", icon: "–", color: "var(--norun)", note: "checks that produced nothing" },
];
const fmt = n => Number(n || 0).toLocaleString("en-US");
const pct = (a, b) => b ? Math.round(100 * a / b) + "%" : "0%";
const KIND = { missing: "Should configure", misconfigured: "Should configure", broken: "Broken" };

// Every value from a scanned system goes in as text, never as markup.
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v; else if (k === "style") e.style.cssText = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return e;
}
const sevBadge = s => h("span", { class: "sev", style: `--c:${SEV[s] || "var(--muted)"}` }, s || "");
const statusDot = s => h("span", { class: "dot", style: `background:${s.color}`, "aria-hidden": "true" }, s.icon);

const totals = D.systems.reduce((t, s) => { for (const k of ["checks", "correct", "should", "broken", "unchecked", "norun"]) t[k] = (t[k] || 0) + (s[k] || 0); return t; }, {});
const openObjects = D.checks.reduce((n, c) => n + c.count, 0);
const state = { tab: "overview", q: "", sev: new Set(), kind: "all", system: "all", selected: null, objq: "", objAll: false };

const tip = document.getElementById("tip");
function tipOn(el, text) {
  el.addEventListener("mousemove", ev => { tip.textContent = text; tip.style.display = "block"; tip.style.left = (ev.clientX + 12) + "px"; tip.style.top = (ev.clientY + 12) + "px"; });
  el.addEventListener("mouseleave", () => tip.style.display = "none");
}

function stackBar(s) {
  const total = ST.reduce((n, x) => n + (s[x.key] || 0), 0);
  const bar = h("div", { class: "stack", role: "img", "aria-label": ST.map(x => `${x.label} ${s[x.key] || 0}`).join(", ") });
  for (const x of ST) {
    const v = s[x.key] || 0; if (!v) continue;
    const seg = h("span", { style: `flex:${v};background:${x.color}` });
    tipOn(seg, `${x.label}: ${fmt(v)} checks (${pct(v, total)})`);
    bar.append(seg);
  }
  return bar;
}
function legend(s) {
  return h("div", { class: "legend" }, ST.map(x => h("span", {}, h("i", { style: `background:${x.color}` }), h("b", {}, fmt(s[x.key] || 0)), x.label.toLowerCase())));
}

const views = {
  overview() {
    const intro = D.systems.length
      ? `Keeper ran ${fmt(totals.checks)} checks on ${D.systems.length} system${D.systems.length === 1 ? "" : "s"}. ${fmt(totals.correct)} found the configuration correct, ${fmt(totals.should)} found something to configure, ${fmt(totals.broken)} found something broken, and ${fmt(totals.unchecked)} could not check. Behind them: ${fmt(openObjects)} open findings across ${fmt(D.checks.length)} checks.`
      : "No scan has results yet. Run 'keeper run' to scan, then build this page again.";
    const tiles = h("div", { class: "grid tiles" }, ST.slice(0, 4).map(x => {
      const go = () => { if (x.key === "correct") show("passed"); else if (x.key === "unchecked") show("unchecked"); else { state.kind = x.key === "broken" ? "broken" : "should"; show("findings"); } };
      return h("div", { class: "card tile", tabindex: "0", role: "button", onclick: go, onkeydown: e => { if (e.key === "Enter") go(); } },
        h("div", { class: "stripe", style: `background:${x.color}` }),
        h("div", { class: "label" }, statusDot(x), x.label),
        h("div", { class: "value" }, fmt(totals[x.key])),
        h("div", { class: "note" }, `${pct(totals[x.key], totals.checks)} of checks · ${x.note}`));
    }));

    const systems = h("div", { class: "card" }, h("h2", {}, "Systems"),
      D.systems.length ? D.systems.map(s => h("div", { class: "sys", tabindex: "0", onclick: () => { state.system = s.system; show("findings"); } },
        h("div", { class: "sysrow" }, h("span", { class: "sysname" }, s.system), h("span", { class: "meta" }, `${s.instance} · scanned ${(s.scanned || "").slice(0, 10)} · ${fmt(s.checks)} checks`)),
        stackBar(s), legend(s))) : h("div", { class: "empty" }, "Nothing scanned yet."),
      D.neverScanned.length ? h("details", {}, h("summary", {}, `${D.neverScanned.length} more systems have rules but were never scanned`),
        h("div", { class: "chips", style: "margin-top:8px" }, D.neverScanned.map(n => h("span", { class: "chip" }, `${n.system} · ${n.rules}`)))) : null);

    const urgent = D.checks.filter(c => c.severity === "critical" || c.severity === "high").slice(0, 8);
    const fixFirst = h("div", { class: "card" }, h("h2", {}, "Fix first"),
      urgent.length ? urgent.map(c => h("div", { class: "row", tabindex: "0", onclick: () => open(c.id), onkeydown: e => { if (e.key === "Enter") open(c.id); } },
        sevBadge(c.severity), h("div", { class: "t" }, h("div", {}, c.title), h("div", { class: "meta" }, `${KIND[c.kind] || c.kind} · ${c.system}`)),
        h("span", { class: "pill" }, fmt(c.count)))) : h("div", { class: "empty" }, "Nothing critical or high is open."));

    const bySev = SEVORDER.map(s => ({ s, checks: D.checks.filter(c => c.severity === s).length, objects: D.checks.filter(c => c.severity === s).reduce((n, c) => n + c.count, 0) })).filter(x => x.checks);
    const max = Math.max(1, ...bySev.map(x => x.objects));
    const sevCard = h("div", { class: "card" }, h("h2", {}, "Open findings by severity"),
      bySev.map(x => {
        const row = h("div", { class: "hbar" }, sevBadge(x.s), h("div", { class: "track" }, h("div", { class: "fill", style: `width:${Math.max(1.5, 100 * x.objects / max)}%;background:${SEV[x.s]}` })),
          h("span", { class: "num" }, `${fmt(x.objects)} objects · ${x.checks} checks`));
        tipOn(row, `${x.s}: ${fmt(x.objects)} affected objects in ${x.checks} checks`);
        return row;
      }),
      h("details", {}, h("summary", {}, "Table view"), h("table", { class: "data" }, h("tr", {}, h("th", {}, "Severity"), h("th", {}, "Checks"), h("th", {}, "Objects")),
        bySev.map(x => h("tr", {}, h("td", {}, x.s), h("td", { class: "n" }, x.checks), h("td", { class: "n" }, fmt(x.objects)))))));

    return [h("h1", {}, "Configuration posture"), h("p", { class: "lede" }, intro), tiles,
      h("div", { class: "grid two" }, h("div", { class: "grid" }, systems), h("div", { class: "grid" }, fixFirst, sevCard))];
  },

  findings() {
    const q = state.q.toLowerCase();
    const list = D.checks.filter(c =>
      (state.kind === "all" || (state.kind === "broken" ? c.kind === "broken" : c.kind !== "broken")) &&
      (state.system === "all" || c.system === state.system) &&
      (!state.sev.size || state.sev.has(c.severity)) &&
      (!q || (c.title + " " + c.id + " " + (c.why || "") + " " + c.objects.map(o => o.join(" ")).join(" ")).toLowerCase().includes(q)));
    if (state.selected && !list.some(c => c.id === state.selected)) state.selected = null;
    if (!state.selected && list.length) state.selected = list[0].id;

    const kindChips = h("div", { class: "chips" }, [["all", "All"], ["should", "Should configure"], ["broken", "Broken"]].map(([k, l]) =>
      h("button", { class: "chip", "aria-pressed": String(state.kind === k), onclick: () => { state.kind = k; render(); } }, l)));
    const sevChips = h("div", { class: "chips" }, SEVORDER.filter(s => D.checks.some(c => c.severity === s)).map(s =>
      h("button", { class: "chip", "aria-pressed": String(state.sev.has(s)), onclick: () => { state.sev.has(s) ? state.sev.delete(s) : state.sev.add(s); render(); } }, s)));
    const sysSel = h("select", { class: "chip", onchange: e => { state.system = e.target.value; render(); } },
      h("option", { value: "all" }, "All systems"), [...new Set(D.checks.map(c => c.system))].sort().map(s => h("option", { value: s, selected: state.system === s }, s)));

    const rows = h("div", { class: "card list", role: "listbox", "aria-label": "Findings" },
      list.length ? list.map(c => h("div", { class: "row", role: "option", tabindex: "0", "aria-selected": String(c.id === state.selected), "data-id": c.id,
        onclick: () => { state.selected = c.id; state.objq = ""; state.objAll = false; location.hash = "findings/" + encodeURIComponent(c.id); render(); } },
        sevBadge(c.severity), h("div", { class: "t" }, h("div", {}, c.title), h("div", { class: "meta" }, `${KIND[c.kind] || c.kind} · ${c.system}`)),
        h("span", { class: "pill" }, fmt(c.count)))) : h("div", { class: "empty" }, "No finding matches."));

    const c = D.checks.find(x => x.id === state.selected);
    return [h("h1", {}, "Findings"), h("p", { class: "lede" }, `${fmt(list.length)} checks with open findings · ${fmt(list.reduce((n, x) => n + x.count, 0))} affected objects. Press `, h("span", { class: "kbd" }, "/"), " to search, ", h("span", { class: "kbd" }, "j"), " ", h("span", { class: "kbd" }, "k"), " to move."),
      h("div", { class: "filters" }, kindChips, sevChips, sysSel),
      h("div", { class: "split" }, rows, c ? detail(c) : h("div", { class: "card empty" }, "Choose a finding."))];
  },

  passed() {
    const q = state.q.toLowerCase();
    const items = D.passed.filter(p => (state.system === "all" || p.system === state.system) && (!q || (p.title + " " + p.id).toLowerCase().includes(q)));
    const groups = [...new Set(items.map(p => p.system))];
    return [h("h1", {}, "Configured correctly"),
      h("p", { class: "lede" }, `Each line is a problem Keeper looked for and did not find anywhere it looked - in a complete, fresh read. ${fmt(items.length)} checks.`),
      groups.length ? groups.map(g => h("div", { class: "card group" }, h("div", { class: "h" }, statusDot(ST[0]), g),
        items.filter(p => p.system === g).map(p => h("div", { class: "ok" }, sevBadge(p.severity),
          h("div", { style: "flex:1" }, h("div", {}, p.title), h("div", { class: "meta" }, `${p.id} · none found in ${fmt(p.passed)} checked${p.override ? " · threshold changed by " + p.override : ""}`)))))) :
        h("div", { class: "card empty" }, "Nothing passes yet: a check counts only when it passed everywhere in a clean, fresh read.")];
  },

  unchecked() {
    const q = state.q.toLowerCase();
    const items = D.unchecked.filter(u => (state.system === "all" || u.system === state.system) && (!q || (u.title + " " + u.id + " " + (u.why || "")).toLowerCase().includes(q)));
    return [h("h1", {}, "What Keeper could not check"),
      h("p", { class: "lede" }, "A check here is neither correct nor a finding: Keeper did not see enough to say. Fix the access or the setting named, and scan again."),
      D.coverage.length ? h("div", { class: "card group" }, h("div", { class: "h" }, "Reads that came back incomplete"),
        D.coverage.map(c => h("div", { class: "ok" }, statusDot(ST[3]), h("div", { style: "flex:1" }, h("div", {}, `${c.system}: ${c.state}`), h("div", { class: "meta" }, c.reason || ""))))) : null,
      h("div", { class: "card group" }, h("div", { class: "h" }, `Checks without an answer (${fmt(items.length)})`),
        items.length ? items.map(u => h("div", { class: "ok" }, sevBadge(u.severity), h("div", { style: "flex:1" }, h("div", {}, u.title), h("div", { class: "meta" }, `${u.system} · ${u.id} · ${u.why || ""}`)))) :
          h("div", { class: "empty" }, "Every check that ran could see its data.")),
      D.neverScanned.length ? h("div", { class: "card group" }, h("div", { class: "h" }, "Never scanned"),
        h("div", { class: "chips" }, D.neverScanned.map(n => h("span", { class: "chip" }, `${n.system} · ${n.rules} rules`)))) : null];
  },
};

function detail(c) {
  const q = state.objq.toLowerCase();
  const objs = c.objects.filter(o => !q || o.join(" ").toLowerCase().includes(q));
  const shown = state.objAll ? objs : objs.slice(0, 300);
  const objList = h("div", {}, shown.map(([name, ev]) => h("div", { class: "obj" },
    ev ? (name && name !== "-" && !ev.toLowerCase().includes(String(name).toLowerCase()) ? [h("b", {}, name), h("span", {}, " — " + ev)] : h("span", {}, ev)) : h("b", {}, name || ""))),
    objs.length > shown.length ? h("div", { class: "obj" }, h("button", { class: "chip", onclick: () => { state.objAll = true; render(); } }, `Show all ${fmt(objs.length)}`)) : null,
    !objs.length ? h("div", { class: "empty" }, "No object matches.") : null);
  const text = () => objs.map(([n, e]) => e || n).join("\n");
  const csv = () => "name,evidence\n" + objs.map(([n, e]) => [n, e].map(v => '"' + String(v ?? "").replace(/"/g, '""') + '"').join(",")).join("\n");
  const download = () => { const a = h("a", { href: URL.createObjectURL(new Blob([csv()], { type: "text/csv" })), download: c.id + ".csv" }); document.body.append(a); a.click(); a.remove(); };
  const filter = h("input", { type: "search", placeholder: `Filter ${fmt(c.count)} objects`, value: state.objq,
    oninput: e => { state.objq = e.target.value; const pos = e.target.selectionStart; render(); const f = document.querySelector(".objs input"); if (f) { f.focus(); f.setSelectionRange(pos, pos); } } });
  return h("div", { class: "card detail" },
    h("div", { style: "display:flex;gap:10px;align-items:center" }, sevBadge(c.severity), h("span", { class: "meta" }, KIND[c.kind] || c.kind)),
    h("h3", {}, c.title),
    h("div", { class: "kv" }, h("span", {}, `Found on ${fmt(c.count)}`), h("span", {}, c.system), h("span", {}, c.id), c.firstSeen ? h("span", {}, `first seen ${c.firstSeen.slice(0, 10)}`) : null, c.security ? h("span", {}, "security") : null),
    c.why ? h("div", { class: "block" }, h("div", { class: "h" }, "Why it matters"), h("div", {}, c.why)) : null,
    c.fix ? h("div", { class: "block" }, h("div", { class: "h" }, "What to do"), h("div", { class: "fix" }, c.fix)) : null,
    c.refs && c.refs.length ? h("div", { class: "block" }, h("div", { class: "h" }, "References"), h("div", { class: "chips" }, c.refs.map(r => h("span", { class: "chip" }, r)))) : null,
    h("div", { class: "block" }, h("div", { class: "h" }, "Where"),
      h("div", { class: "objs" }, h("div", { class: "tools" }, filter,
        h("button", { class: "chip", onclick: e => { navigator.clipboard && navigator.clipboard.writeText(text()); e.target.textContent = "Copied"; } }, "Copy"),
        h("button", { class: "chip", onclick: download }, "CSV")), objList)));
}

function open(id) { state.selected = id; state.kind = "all"; state.sev.clear(); state.system = "all"; state.objq = ""; show("findings"); }
function show(tab) { state.tab = tab; if (tab !== "findings" || !state.selected) location.hash = tab; else location.hash = "findings/" + encodeURIComponent(state.selected); render(); window.scrollTo(0, 0); }

const TABS = [["overview", "Overview"], ["findings", "Findings"], ["passed", "Correct"], ["unchecked", "Couldn't check"]];
function render() {
  const nav = document.getElementById("nav"); nav.replaceChildren(...TABS.map(([k, l]) => h("button", { "aria-current": state.tab === k ? "page" : null, onclick: () => show(k) }, l)));
  document.getElementById("main").replaceChildren(...views[state.tab](), h("div", { class: "foot" }, `Generated ${D.generated} by keeper · read-only · nothing in this page was fetched from anywhere`));
}

document.getElementById("sub").textContent = [D.tenant, D.generated].filter(Boolean).join(" · ");
const qInput = document.getElementById("q");
qInput.addEventListener("input", () => { state.q = qInput.value; if (state.tab === "overview" && state.q) state.tab = "findings"; render(); });
document.getElementById("theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("keeper-theme", document.documentElement.dataset.theme); } catch { }
});
try { const t = localStorage.getItem("keeper-theme"); if (t) document.documentElement.dataset.theme = t; } catch { }
document.addEventListener("keydown", e => {
  if (e.target.matches("input, select")) { if (e.key === "Escape") e.target.blur(); return; }
  if (e.key === "/") { e.preventDefault(); qInput.focus(); }
  if (state.tab === "findings" && (e.key === "j" || e.key === "k")) {
    const ids = [...document.querySelectorAll(".list .row")].map(r => r.dataset.id); const i = ids.indexOf(state.selected);
    const next = ids[Math.min(ids.length - 1, Math.max(0, i + (e.key === "j" ? 1 : -1)))];
    if (next) { state.selected = next; state.objq = ""; state.objAll = false; render(); document.querySelector('.list .row[aria-selected="true"]')?.scrollIntoView({ block: "nearest" }); }
  }
});
const m = location.hash.slice(1).split("/");
if (TABS.some(([k]) => k === m[0])) state.tab = m[0];
if (m[0] === "findings" && m[1]) state.selected = decodeURIComponent(m[1]);
render();
</script>
</body></html>
""";
}
