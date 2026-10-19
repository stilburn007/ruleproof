# Security

## Reporting

Do not open a public issue for a vulnerability that could expose credentials or
enable destructive agent behavior. Use GitHub's private vulnerability reporting
for this repository.

Include:

- The affected Ruleproof version.
- A minimal instruction file that demonstrates the issue.
- Whether the problem is a false negative, false positive, or code execution
  vulnerability.
- Any suggested remediation.

## Scope

Ruleproof only reads repository files. It does not execute commands found in
instruction files. Reports may contain instruction text, so review generated
JSON, HTML, and SARIF files before publishing them from a private repository.

Secret evidence is truncated in reports, but the surrounding instruction text
is preserved to make findings actionable.
