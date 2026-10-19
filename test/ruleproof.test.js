import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { reportHtml } from "../src/html-report.js";
import { reportBadge, reportJson, reportSarif } from "../src/reporters.js";
import { scan, shouldFail } from "../src/scan.js";
import { globToRegExp, matchesAnyGlob } from "../src/util.js";

const directory = path.dirname(fileURLToPath(import.meta.url));
const conflicted = path.join(directory, "fixtures", "conflicted");
const clean = path.join(directory, "fixtures", "clean");

test("finds cross-file package manager conflicts", async () => {
  const result = await scan(conflicted);
  assert.ok(result.findings.some((finding) => finding.rule === "package-manager-conflict"));
  assert.ok(result.findings.some((finding) => finding.rule === "package-manager-mismatch"));
  assert.ok(result.score < 100);
});

test("validates commands, paths, and file scope", async () => {
  const result = await scan(conflicted);
  const rules = new Set(result.findings.map((finding) => finding.rule));
  assert.ok(rules.has("broken-command"));
  assert.ok(rules.has("broken-reference"));
  assert.ok(rules.has("file-scope-conflict"));
  assert.ok(rules.has("format-conflict"));
  assert.ok(rules.has("command-conflict"));
  assert.ok(rules.has("commit-policy-conflict"));
});

test("detects security hazards and redacts evidence", async () => {
  const result = await scan(conflicted);
  assert.ok(result.findings.some((finding) => finding.rule === "prompt-injection"));
  assert.ok(result.findings.some((finding) => finding.rule === "dangerous-command"));
  assert.ok(result.findings.some((finding) => finding.rule === "absolute-path"));
});

test("detects credentials and redacts report evidence", async () => {
  const directoryPath = await fs.mkdtemp(path.join(os.tmpdir(), "ruleproof-secret-"));
  const token = ["ghp", "a".repeat(36)].join("_");
  try {
    await fs.writeFile(
      path.join(directoryPath, "AGENTS.md"),
      `# Test\n\n- Use this key: ${token}\n`,
    );
    const result = await scan(directoryPath);
    const secret = result.findings.find((finding) => finding.rule === "secret-detected");
    assert.ok(secret);
    assert.match(secret.evidence, /^ghp_\.\.\./);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(token));
  } finally {
    await fs.rm(directoryPath, { recursive: true, force: true });
  }
});

test("audits MCP server configuration", async () => {
  const result = await scan(conflicted);
  const rules = new Set(result.findings.map((finding) => finding.rule));
  assert.ok(rules.has("mcp-unpinned-server"));
  assert.ok(rules.has("mcp-insecure-transport"));
  assert.equal(result.stats.mcpFiles, 1);
});

test("accepts a consistent repository", async () => {
  const result = await scan(clean);
  assert.equal(result.findings.length, 0);
  assert.equal(result.score, 100);
  assert.equal(shouldFail(result), false);
});

test("supports JSON and SARIF reports", async () => {
  const result = await scan(conflicted);
  const json = JSON.parse(reportJson(result));
  assert.equal(json.tool.name, "ruleproof");
  assert.ok(json.findings.length > 0);

  const sarif = JSON.parse(reportSarif(result));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.name, "ruleproof");
  assert.ok(sarif.runs[0].results.length > 0);
});

test("generates an SVG score badge", async () => {
  const result = await scan(clean);
  const badge = reportBadge(result);
  assert.match(badge, /^<svg /);
  assert.match(badge, /100\/100/);
  assert.match(badge, /#176b4d/);
});

test("HTML report escapes instruction text", async () => {
  const result = await scan(conflicted);
  const html = reportHtml(result);
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Instruction conflict report/);
  assert.doesNotMatch(html, /<script>alert/);
});

test("glob helper handles recursive patterns", () => {
  assert.equal(matchesAnyGlob(".cursor/rules/style.mdc", [".cursor/rules/**"]), true);
  assert.equal(matchesAnyGlob("src/app.ts", ["**/*.ts"]), true);
  assert.equal(matchesAnyGlob("README.md", ["**/*.ts"]), false);
  assert.ok(globToRegExp("src/*.js").test("src/index.js"));
});
