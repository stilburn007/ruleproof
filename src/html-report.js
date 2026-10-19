import { RULES } from "./rules.js";
import { escapeHtml, formatNumber } from "./util.js";

function scoreClass(score) {
  if (score >= 90) return "good";
  if (score >= 70) return "warn";
  return "bad";
}

function severityClass(severity) {
  return severity === "error" ? "bad" : severity === "warning" ? "warn" : "info";
}

function findingHtml(finding) {
  const locations = finding.files
    .map(
      (file) =>
        `<span class="location">${escapeHtml(file.path)}${file.line ? `:${file.line}` : ""}</span>`,
    )
    .join("");
  const evidence = finding.evidence
    ? `<pre class="evidence">${escapeHtml(finding.evidence)}</pre>`
    : "";
  const suggestion = finding.suggestion
    ? `<p class="suggestion"><span>Fix</span>${escapeHtml(finding.suggestion)}</p>`
    : "";

  return `<article class="finding ${severityClass(finding.severity)}">
    <div class="finding-head">
      <span class="severity">${escapeHtml(finding.severity)}</span>
      <span class="rule">${escapeHtml(finding.rule)}</span>
      <span class="rule-title">${escapeHtml(RULES[finding.rule]?.title ?? "")}</span>
    </div>
    <h3>${escapeHtml(finding.message)}</h3>
    <div class="locations">${locations || '<span class="location">repository</span>'}</div>
    ${evidence}
    ${suggestion}
  </article>`;
}

function fileRows(result) {
  return [...result.files, ...(result.mcpFiles ?? []).map((file) => ({
    path: file.path,
    kind: "MCP config",
    tokens: 0,
    directives: 0,
  }))]
    .map(
      (file) => `<tr>
        <td class="mono">${escapeHtml(file.path)}</td>
        <td>${escapeHtml(file.kind)}</td>
        <td class="number">${formatNumber(file.tokens)}</td>
        <td class="number">${formatNumber(file.directives)}</td>
      </tr>`,
    )
    .join("");
}

export function reportHtml(result) {
  const generated = new Date().toISOString();
  const findingMarkup =
    result.findings.length > 0
      ? result.findings.map(findingHtml).join("\n")
      : `<div class="empty">
          <p>No conflicts, broken references, or unsafe instructions found.</p>
        </div>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Ruleproof report: ${escapeHtml(result.project)}</title>
  <style>
    :root {
      --ink: #18202d;
      --muted: #637083;
      --paper: #f5f6f8;
      --panel: #ffffff;
      --line: #d9dee6;
      --blue: #1d4ed8;
      --green: #087f5b;
      --amber: #a84f00;
      --red: #b42318;
      --violet: #7048b6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      background: var(--paper);
      font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .wrap { width: min(1120px, calc(100% - 40px)); margin: 0 auto; padding: 36px 0 64px; }
    header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 32px;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--line);
    }
    .eyebrow { margin: 0 0 6px; color: var(--violet); font: 700 12px/1.2 ui-monospace, monospace; letter-spacing: .08em; }
    h1 { margin: 0; font-size: 30px; line-height: 1.1; letter-spacing: 0; }
    .project { margin-top: 8px; color: var(--muted); }
    .score {
      display: grid;
      place-items: center;
      min-width: 118px;
      min-height: 88px;
      border: 1px solid currentColor;
      border-radius: 6px;
      font: 800 34px/1 ui-monospace, monospace;
    }
    .score small { display: block; margin-top: 5px; font: 600 10px/1 ui-sans-serif, sans-serif; text-transform: uppercase; }
    .good { color: var(--green); }
    .warn { color: var(--amber); }
    .bad { color: var(--red); }
    .info { color: var(--blue); }
    .stats {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin: 22px 0 28px;
    }
    .stat {
      padding: 15px 16px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
    }
    .stat span { display: block; color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .stat strong { display: block; margin-top: 4px; font: 700 24px/1.2 ui-monospace, monospace; }
    section { margin-top: 30px; }
    h2 { margin: 0 0 12px; font-size: 18px; letter-spacing: 0; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; }
    th { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    tr:last-child td { border-bottom: 0; }
    .number { text-align: right; font-family: ui-monospace, monospace; }
    .mono, .location, .evidence, .rule { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
    .findings { display: grid; gap: 12px; }
    .finding {
      padding: 18px 20px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-left-width: 5px;
      border-radius: 6px;
    }
    .finding.bad { border-left-color: var(--red); }
    .finding.warn { border-left-color: var(--amber); }
    .finding.info { border-left-color: var(--blue); }
    .finding-head { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
    .severity {
      padding: 2px 6px;
      border: 1px solid currentColor;
      border-radius: 3px;
      font-size: 10px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .rule { color: var(--violet); font-size: 12px; }
    .rule-title { color: var(--muted); font-size: 12px; }
    .finding h3 { margin: 12px 0 8px; font-size: 16px; line-height: 1.35; }
    .locations { display: flex; flex-wrap: wrap; gap: 6px; }
    .location { padding: 2px 6px; border-radius: 3px; background: #eef1f5; color: #354052; font-size: 12px; }
    .evidence { margin: 12px 0 0; padding: 12px; overflow: auto; background: #f7f8fa; border: 1px solid #e3e7ed; font-size: 12px; white-space: pre-wrap; }
    .suggestion { margin: 12px 0 0; color: #354052; }
    .suggestion span { margin-right: 8px; color: var(--violet); font-size: 11px; font-weight: 800; text-transform: uppercase; }
    .empty { padding: 28px; border: 1px solid #9ed0bf; border-radius: 6px; background: #effaf5; color: #075c42; }
    footer { margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
    @media (max-width: 720px) {
      .wrap { width: min(100% - 24px, 1120px); padding-top: 24px; }
      header { flex-direction: column; }
      .score { min-width: 100%; min-height: 72px; }
      .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      table { display: block; overflow-x: auto; }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <header>
      <div>
        <p class="eyebrow">RULEPROOF / AGENT INSTRUCTION AUDIT</p>
        <h1>Instruction conflict report</h1>
        <div class="project">${escapeHtml(result.project)}</div>
      </div>
      <div class="score ${scoreClass(result.score)}">
        ${result.score}
        <small>of 100</small>
      </div>
    </header>

    <div class="stats">
      <div class="stat"><span>Instruction files</span><strong>${result.stats.files}</strong></div>
      <div class="stat"><span>Directives</span><strong>${result.stats.directives}</strong></div>
      <div class="stat"><span>Approx. tokens</span><strong>${formatNumber(result.stats.tokens)}</strong></div>
      <div class="stat"><span>MCP configs</span><strong>${result.stats.mcpFiles ?? 0}</strong></div>
    </div>

    <section>
      <h2>Files</h2>
      <table>
        <thead><tr><th>Path</th><th>Agent</th><th class="number">Tokens</th><th class="number">Rules</th></tr></thead>
        <tbody>${fileRows(result)}</tbody>
      </table>
    </section>

    <section>
      <h2>Findings</h2>
      <div class="findings">${findingMarkup}</div>
    </section>

    <footer>Generated by Ruleproof ${escapeHtml(result.tool.version)} at ${escapeHtml(generated)}. No files were uploaded.</footer>
  </main>
</body>
</html>
`;
}
