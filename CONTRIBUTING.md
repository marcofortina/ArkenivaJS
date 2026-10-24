# Contributing to ArkenivaJS

Use Node.js 24 and the exact pnpm version in `package.json`. The compatibility workflow also runs on Node.js 22 and 26. Install with `pnpm install --frozen-lockfile`; use `pnpm verify` before proposing a change. The command checks formatting, lint, builds, types, unit/contract/property coverage, executable guides, API documentation and smoke behavior.

All source comments, JSDoc/TSDoc, developer-facing errors, technical product documentation and Git commit messages must be written in English. Keep public ESM exports explicit, TypeScript strict and dependencies within their owning packages. Add each driver only to its own adapter. Avoid import-time resource creation and required mutable global singletons.

A public behavior change includes its meaningful positive, negative, failure and cancellation tests. Parser and state-machine changes need seeded property tests. Rebuild before running examples. Maintain package READMEs, the API reference and a runnable consumer example with expected output and cleanup. Product error messages and log tests must use fake credentials and verify their redaction.

`pnpm docs:build` renders the API reference under `.build/api` and checks local Markdown links. Component ports intentionally omitted from direct package exports are described through the application interface; they do not imply an installed runtime adapter. API documentation treats broken links and converter warnings as errors. Keep build outputs and local reports outside version control.

Use focused commits and keep main reproducibly buildable. Each commit should describe one logical behavior and include the tests that make it reviewable. Verify dependency release sources, licenses and compatibility before changing exact pins. GitHub Actions must use full immutable commit references and read-only permissions for pull request jobs. Run `pnpm audit --audit-level=high` after dependency changes.

Mermaid diagrams are optional. If a diagram is added, include a pinned renderer and a successful rendering check; the documentation gate rejects unconfigured Mermaid blocks. Keep a complete textual explanation alongside a diagram.

`pnpm test` and coverage select unit, contract and property suites. Integration suites are separate mandatory jobs with disposable external services; `pnpm test:integration:telemetry` requires the real collector and an external evidence path. Missing infrastructure fails the suite instead of skipping it. See the [telemetry reference](packages/telemetry/README.md).
