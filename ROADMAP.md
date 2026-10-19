# Roadmap

## Next

- Scope conflicts by monorepo package instead of treating the repository as one
  instruction surface.
- Parse MCP server configuration for remote transports, broad filesystem
  access, and unpinned command execution.
- Add editor diagnostics through an LSP-compatible server.
- Add `ruleproof explain <rule>` with examples and remediation guidance.
- Publish a stable JSON schema for CI integrations.

## Later

- Suggest a minimal merged instruction file without rewriting user intent.
- Compare instruction drift between the default branch and a pull request.
- Add adapters for more agent-specific configuration formats.

The project will not upload repository content or require an LLM API key for
core checks.
