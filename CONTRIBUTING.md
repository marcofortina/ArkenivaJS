# Contributing to ArkenivaJS

Use Node.js 24 and the exact pnpm version in `package.json`. The compatibility workflow also runs on Node.js 22 and 26. Install with `pnpm install --frozen-lockfile`; use `pnpm verify` before proposing a change. The command checks formatting, lint, builds, types, unit/contract/property coverage, executable guides, API documentation and smoke behavior.

All source comments, JSDoc/TSDoc, developer-facing errors, technical product documentation and Git commit messages must be written in English. Keep public ESM exports explicit, TypeScript strict and dependencies within their owning packages. Add each driver only to its own adapter. Avoid import-time resource creation and required mutable global singletons.

A public behavior change includes its meaningful positive, negative, failure and cancellation tests. Parser and state-machine changes need seeded property tests. Rebuild before running examples. Maintain package READMEs, the API reference and a runnable consumer example with expected output and cleanup. Product error messages and log tests must use fake credentials and verify their redaction.

`pnpm docs:build` renders the API reference under `.build/api` and checks local Markdown links. Component ports intentionally omitted from direct package exports are described through the application interface; they do not imply an installed runtime adapter. API documentation treats broken links and converter warnings as errors. Keep build outputs and local reports outside version control.

Work directly on main with focused commits that keep it reproducibly buildable. Each commit should describe one logical behavior and include the tests that make it reviewable. Do not create development branches or pull requests. Pass applicable local checks before a normal fast-forward push to origin/main, then verify mandatory GitHub Actions on the exact pushed commit. A failed mandatory job blocks further development until a corrective main commit or revert passes. GitHub Actions run only on pushes to main, with full immutable action references and read-only permissions. Verify dependency release sources, licenses and compatibility before changing exact pins. Run `pnpm audit --audit-level=high` after dependency changes.

Mermaid diagrams are optional. If a diagram is added, include a pinned renderer and a successful rendering check; the documentation gate rejects unconfigured Mermaid blocks. Keep a complete textual explanation alongside a diagram.

`pnpm test` and coverage select unit, contract and property suites. Integration suites are separate mandatory jobs with disposable external services; `pnpm test:integration:telemetry` requires the real collector and an external evidence path. Missing infrastructure fails the suite instead of skipping it. See the [telemetry reference](packages/telemetry/README.md).

TLS rejection tests require the OpenSSL CLI already present on the supported Ubuntu CI image. They create private keys only in protected temporary directories, trust the test CA only in a short-lived child process, and remove all certificate material after the test. No private certificate/key is versioned.

POSIX JSONL resource-failure tests use the Ubuntu Bash builtin file-size limit and the preinstalled `prlimit` utility in a short-lived child process. They handle `SIGXFSZ` only in that child, verify an actual failed write and rollback of partial data, and restore that child's original limit before V8 emits coverage. The parent and system limits remain unaffected.

`pnpm test:package:messaging` verifies packed portable messaging exports with
an unpatched SDK in a private temporary consumer. The separate NATS matrix
requires verified TLS, scoped accounts, negative transport tests, actual
telemetry export and independent metering. See the
[NATS fixture](packages/messaging/test/fixtures/README.md).
