import path from "node:path";
import { runChecks } from "./checks.js";
import { loadConfig } from "./config.js";
import { discoverInstructionFiles, discoverMcpConfigs } from "./files.js";
import { parseInstructions } from "./parser.js";
import { compareSeverity, matchesAnyGlob, severityRank } from "./util.js";

const SEVERITY_WEIGHTS = {
  error: 16,
  warning: 6,
  info: 1,
};

function isAllowed(finding, allow = []) {
  return allow.some((entry) => {
    if (entry.rule !== finding.rule) return false;
    if (!entry.path) return true;
    return finding.files.some((file) => matchesAnyGlob(file.path, [entry.path]));
  });
}

function scoreFindings(findings) {
  const deduction = findings.reduce(
    (sum, finding) => sum + (SEVERITY_WEIGHTS[finding.severity] ?? 0),
    0,
  );
  return Math.max(0, 100 - deduction);
}

function normalizeFinding(finding) {
  return {
    ...finding,
    files: [...finding.files].sort((left, right) => {
      const byPath = left.path.localeCompare(right.path);
      if (byPath !== 0) return byPath;
      return (left.line ?? 0) - (right.line ?? 0);
    }),
  };
}

export async function scan(target = ".", options = {}) {
  const startedAt = Date.now();
  const root = path.resolve(options.cwd ?? process.cwd(), target);
  const { config, path: configPath } = await loadConfig(root, options.config);
  const files = await discoverInstructionFiles(root, config);
  const mcpFiles = await discoverMcpConfigs(root, config);
  const instructions = parseInstructions(files);
  const rawFindings = await runChecks(root, instructions, config, mcpFiles);
  const findings = rawFindings
    .filter((finding) => !isAllowed(finding, config.allow))
    .map(normalizeFinding)
    .sort((left, right) => {
      const bySeverity = compareSeverity(left.severity, right.severity);
      if (bySeverity !== 0) return bySeverity;
      const leftFile = left.files[0]?.path ?? "";
      const rightFile = right.files[0]?.path ?? "";
      return leftFile.localeCompare(rightFile) || left.message.localeCompare(right.message);
    });

  const counts = {
    error: findings.filter((finding) => finding.severity === "error").length,
    warning: findings.filter((finding) => finding.severity === "warning").length,
    info: findings.filter((finding) => finding.severity === "info").length,
  };
  const tokens = instructions.reduce((sum, file) => sum + file.tokens, 0);
  const directives = instructions.reduce((sum, file) => sum + file.directives.length, 0);

  return {
    schemaVersion: 1,
    tool: {
      name: "ruleproof",
      version: options.version ?? "0.1.0",
    },
    project: path.basename(root),
    score: scoreFindings(findings),
    counts,
    stats: {
      files: instructions.length,
      directives,
      tokens,
      mcpFiles: mcpFiles.length,
      durationMs: Date.now() - startedAt,
    },
    files: instructions.map((file) => ({
      path: file.path,
      kind: file.kind,
      tokens: file.tokens,
      directives: file.directives.length,
    })),
    mcpFiles: mcpFiles.map((file) => ({ path: file.path })),
    findings,
    configPath: configPath ? path.basename(configPath) : null,
    config,
  };
}

export function shouldFail(result, options = {}) {
  const failOn = options.failOn ?? result.config.failOn ?? "error";
  const threshold = failOn === "never" ? Number.POSITIVE_INFINITY : severityRank(failOn);
  const severityFailure = result.findings.some(
    (finding) => severityRank(finding.severity) >= threshold,
  );
  const minScore = options.minScore ?? result.config.minScore ?? 0;
  return severityFailure || result.score < minScore;
}
