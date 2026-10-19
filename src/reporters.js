import { RULES, listRules } from "./rules.js";
import { formatNumber, severityRank } from "./util.js";

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};

const SEVERITY_COLOR = {
  error: ANSI.red,
  warning: ANSI.yellow,
  info: ANSI.blue,
};

function colorize(enabled, color, value) {
  return enabled ? `${color}${value}${ANSI.reset}` : String(value);
}

function severityLabel(finding, color) {
  const label = finding.severity.toUpperCase().padEnd(7);
  return colorize(color, SEVERITY_COLOR[finding.severity] ?? "", label);
}

function locationLabel(finding) {
  if (finding.files.length === 0) return "repository";
  return finding.files
    .map((file) => `${file.path}${file.line ? `:${file.line}` : ""}`)
    .join(", ");
}

export function reportPretty(result, options = {}) {
  const color = Boolean(options.color);
  const verbose = Boolean(options.verbose);
  const lines = [];
  const title = colorize(color, ANSI.bold, "RULEPROOF");
  const grade =
    result.score >= 90 ? "PASS" : result.score >= 70 ? "REVIEW" : "FAIL";
  const gradeColor =
    result.score >= 90 ? ANSI.green : result.score >= 70 ? ANSI.yellow : ANSI.red;

  lines.push(
    `${title}  ${colorize(color, gradeColor, grade)}  ${colorize(
      color,
      ANSI.dim,
      `${result.project}  score ${result.score}/100`,
    )}`,
  );
  lines.push(
    `${result.stats.files} instruction files | ${result.stats.directives} directives | ~${formatNumber(
      result.stats.tokens,
    )} tokens`,
  );
  lines.push("");

  if (result.files.length > 0) {
    lines.push(colorize(color, ANSI.bold, "FILES"));
    const width = Math.min(52, Math.max(...result.files.map((file) => file.path.length)));
    for (const file of result.files) {
      const pathLabel = file.path.padEnd(width);
      lines.push(
        `  ${pathLabel}  ${String(file.tokens).padStart(6)} tok  ${String(
          file.directives,
        ).padStart(3)} rules  ${file.kind}`,
      );
    }
    lines.push("");
  }

  if (result.mcpFiles?.length > 0) {
    lines.push(colorize(color, ANSI.bold, "MCP CONFIGS"));
    for (const file of result.mcpFiles) {
      lines.push(`  ${file.path}`);
    }
    lines.push("");
  }

  if (result.findings.length === 0) {
    lines.push(colorize(color, ANSI.green, "No conflicts, broken references, or unsafe instructions found."));
  } else {
    lines.push(colorize(color, ANSI.bold, "FINDINGS"));
    for (const finding of result.findings) {
      lines.push(
        `  ${severityLabel(finding, color)} ${colorize(
          color,
          ANSI.magenta,
          finding.rule,
        )}  ${finding.message}`,
      );
      lines.push(`        ${colorize(color, ANSI.dim, locationLabel(finding))}`);
      if (verbose && finding.evidence) {
        for (const evidenceLine of finding.evidence.split(/\r?\n/)) {
          lines.push(`        ${colorize(color, ANSI.dim, `| ${evidenceLine}`)}`);
        }
      }
      if (finding.suggestion) {
        lines.push(`        ${colorize(color, ANSI.cyan, "fix")} ${finding.suggestion}`);
      }
      lines.push("");
    }
  }

  const counts = `${result.counts.error} errors, ${result.counts.warning} warnings, ${result.counts.info} info`;
  lines.push(
    `${colorize(color, ANSI.bold, "RESULT")}  ${counts}  |  score ${colorize(
      color,
      gradeColor,
      `${result.score}/100`,
    )}`,
  );

  return `${lines.join("\n").trimEnd()}\n`;
}

export function reportJson(result) {
  const output = { ...result };
  delete output.config;
  return `${JSON.stringify(output, null, 2)}\n`;
}

export function reportMarkdown(result) {
  const lines = [];
  lines.push("## Ruleproof");
  lines.push("");
  lines.push(
    `**Score:** ${result.score}/100 | **Files:** ${result.stats.files} | **Directives:** ${result.stats.directives} | **Tokens:** ~${formatNumber(result.stats.tokens)} | **MCP configs:** ${result.stats.mcpFiles ?? 0}`,
  );
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No conflicts, broken references, or unsafe instructions found.");
    return `${lines.join("\n")}\n`;
  }

  lines.push("| Severity | Rule | Finding | Location |");
  lines.push("| --- | --- | --- | --- |");
  for (const finding of result.findings) {
    const message = finding.message.replace(/\|/g, "\\|");
    const location = locationLabel(finding).replace(/\|/g, "\\|");
    lines.push(`| ${finding.severity} | \`${finding.rule}\` | ${message} | ${location} |`);
  }
  lines.push("");
  lines.push(
    `_${result.counts.error} errors, ${result.counts.warning} warnings, ${result.counts.info} info_`,
  );
  return `${lines.join("\n")}\n`;
}

export function reportGithub(result) {
  const lines = [];
  for (const finding of result.findings) {
    const command =
      finding.severity === "error"
        ? "error"
        : finding.severity === "warning"
          ? "warning"
          : "notice";
    const file = finding.files[0];
    const properties = [];
    if (file) {
      properties.push(`file=${file.path}`);
      if (file.line) properties.push(`line=${file.line}`);
    }
    if (finding.rule) properties.push(`title=Ruleproof: ${finding.rule}`);
    const message = `${finding.message}${finding.suggestion ? ` Fix: ${finding.suggestion}` : ""}`;
    lines.push(`::${command} ${properties.join(",")}::${message}`);
  }
  lines.push(
    `::notice title=Ruleproof score::${result.score}/100, ${result.counts.error} errors, ${result.counts.warning} warnings`,
  );
  return `${lines.join("\n")}\n`;
}

function sarifLevel(severity) {
  if (severity === "error") return "error";
  if (severity === "warning") return "warning";
  return "note";
}

export function reportSarif(result) {
  const ruleIds = [...new Set(result.findings.map((finding) => finding.rule))];
  const rules = ruleIds.map((id) => ({
    id,
    name: RULES[id]?.title ?? id,
    shortDescription: { text: RULES[id]?.title ?? id },
    defaultConfiguration: {
      level: sarifLevel(RULES[id]?.severity ?? "warning"),
    },
  }));

  const results = result.findings.map((finding) => {
    const item = {
      ruleId: finding.rule,
      level: sarifLevel(finding.severity),
      message: {
        text: finding.suggestion
          ? `${finding.message} Fix: ${finding.suggestion}`
          : finding.message,
      },
      properties: {
        severity: finding.severity,
      },
    };
    if (finding.files.length > 0) {
      item.locations = finding.files.map((file) => ({
        physicalLocation: {
          artifactLocation: { uri: file.path },
          region: { startLine: file.line ?? 1 },
        },
      }));
    }
    return item;
  });

  return `${JSON.stringify(
    {
      $schema:
        "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "ruleproof",
              informationUri: "https://github.com/stilburn007/ruleproof",
              rules,
            },
          },
          results,
          properties: {
            score: result.score,
            stats: result.stats,
          },
        },
      ],
    },
    null,
    2,
  )}\n`;
}

export function reportBadge(result) {
  const label = "agent instructions";
  const score = `${result.score}/100`;
  const color = result.score >= 90 ? "#176b4d" : result.score >= 70 ? "#a84f00" : "#b42318";
  const labelWidth = 116;
  const scoreWidth = 58;
  const width = labelWidth + scoreWidth;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="Ruleproof: ${score}">
  <title>Ruleproof: ${score}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".18"/>
    <stop offset="1" stop-opacity=".12"/>
  </linearGradient>
  <clipPath id="r"><rect width="${width}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#303846"/>
    <rect x="${labelWidth}" width="${scoreWidth}" height="20" fill="${color}"/>
    <rect width="${width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelWidth / 2}" y="15">${label}</text>
    <text x="${labelWidth + scoreWidth / 2}" y="15" font-weight="700">${score}</text>
  </g>
</svg>
`;
}

export function reportRules() {
  const lines = ["RULEPROOF RULES", ""];
  for (const rule of listRules().sort((left, right) => severityRank(right.severity) - severityRank(left.severity))) {
    lines.push(`  ${rule.id.padEnd(28)} ${rule.severity.padEnd(8)} ${rule.title}`);
  }
  return `${lines.join("\n")}\n`;
}
