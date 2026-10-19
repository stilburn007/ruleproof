# Contributing

Ruleproof is intentionally small: one runtime package, no dependencies, and
deterministic checks that work in local development and CI.

## Development

```bash
git clone https://github.com/stilburn007/ruleproof.git
cd ruleproof
npm test
npm run check
node bin/ruleproof.js test/fixtures/conflicted --verbose
```

## Adding a rule

1. Add the rule metadata to `src/rules.js`.
2. Implement the check in `src/checks.js`.
3. Add both a triggering case and a near-miss case to the fixtures and tests.
4. Document the rule in `README.md`.
5. Run `npm test` and `npm run check`.

Prefer checks that can explain a problem with a precise file and line. A rule
that produces noisy results is worse than no rule.

## Pull requests

Keep changes focused. Include a small reproduction in the PR description when
fixing a false positive or false negative. New runtime dependencies need a
strong justification because zero-dependency installation is part of the
product promise.
