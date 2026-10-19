export const RULES = Object.freeze({
  "secret-detected": {
    severity: "error",
    title: "Credential in agent instructions",
  },
  "private-key-detected": {
    severity: "error",
    title: "Private key in agent instructions",
  },
  "prompt-injection": {
    severity: "error",
    title: "Suspicious instruction override",
  },
  "dangerous-command": {
    severity: "error",
    title: "Destructive or unsafe command",
  },
  "mcp-config-invalid": {
    severity: "error",
    title: "Invalid MCP configuration",
  },
  "mcp-unpinned-server": {
    severity: "warning",
    title: "MCP server package is not pinned",
  },
  "mcp-insecure-transport": {
    severity: "warning",
    title: "MCP server uses an insecure transport",
  },
  "package-manager-conflict": {
    severity: "error",
    title: "Conflicting package managers",
  },
  "package-manager-mismatch": {
    severity: "warning",
    title: "Instructions disagree with repository metadata",
  },
  "format-conflict": {
    severity: "warning",
    title: "Conflicting formatting rules",
  },
  "file-scope-conflict": {
    severity: "error",
    title: "A file is both required and forbidden",
  },
  "command-conflict": {
    severity: "warning",
    title: "Conflicting workflow commands",
  },
  "commit-policy-conflict": {
    severity: "warning",
    title: "Conflicting commit policy",
  },
  "broken-command": {
    severity: "error",
    title: "Instruction points to a missing command",
  },
  "broken-reference": {
    severity: "warning",
    title: "Instruction points to a missing path",
  },
  "token-budget": {
    severity: "warning",
    title: "Instruction context is too large",
  },
  "duplicate-instruction": {
    severity: "info",
    title: "Repeated instruction",
  },
  "absolute-path": {
    severity: "warning",
    title: "Machine-specific absolute path",
  },
  "no-instructions": {
    severity: "info",
    title: "No agent instructions found",
  },
});

export function listRules() {
  return Object.entries(RULES).map(([id, rule]) => ({
    id,
    ...rule,
  }));
}

export function ruleSeverity(id, config = {}) {
  const override = config.rules?.[id];
  if (override === "off") {
    return null;
  }
  if (["info", "warning", "error"].includes(override)) {
    return override;
  }
  return RULES[id]?.severity ?? "warning";
}
