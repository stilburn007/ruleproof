# Ruleproof repository guide

## Commands

- Use `npm` for repository scripts.
- Run `npm test` before submitting a change.
- Run `npm run check` to audit this repository's agent instructions.

## Structure

- CLI entry point: `bin/ruleproof.js`.
- Scanner and checks: `src/`.
- Tests: `test/ruleproof.test.js`.
- Intentional conflict fixtures: `test/fixtures/conflicted/`.

## Constraints

- Keep the runtime dependency-free.
- Support Node.js 20 and newer.
- Do not edit generated report files under the repository root.
- Add a focused test for every new rule or parser behavior.
