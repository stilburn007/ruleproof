# Changelog

## 0.1.0 - 2026-10-19

- Initial release.
- Scans AGENTS.md, CLAUDE.md, GEMINI.md, Cursor rules, Windsurf rules, Cline
  rules, Copilot instructions, and nested AGENTS.md files.
- Detects package manager, formatting, path ownership, test command, and commit
  policy conflicts.
- Validates package scripts, Make targets, just recipes, and repository paths.
- Detects credentials, private keys, prompt injection, dangerous shell
  patterns, and machine-specific paths.
- Audits MCP server configuration for invalid JSON, unpinned packages,
  plaintext HTTP, unsafe commands, and machine-bound paths.
- Reports token budget, duplicated instructions, JSON, Markdown, GitHub
  annotations, SARIF, standalone HTML, and SVG score badges.
- Adds a dependency-free GitHub Action.
