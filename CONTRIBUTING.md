# Contributing to ArkenivaJS

Use Node.js 24 and the exact pnpm version in `package.json`. The compatibility workflow also runs on Node.js 22 and 26. Install with `pnpm install --frozen-lockfile`; use `pnpm verify` before proposing a change. The command checks formatting, lint, builds, types, unit/contract/property coverage, executable guides, API documentation and smoke behavior.

See the [compatibility policy](docs/compatibility.md) for configured architecture
checks and the evidence required before claiming another platform is supported.

All source comments, JSDoc/TSDoc, developer-facing errors, technical product documentation and Git commit messages must be written in English. Keep public ESM exports explicit, TypeScript strict and dependencies within their owning packages. Add each driver only to its own adapter. Avoid import-time resource creation and required mutable global singletons.

A public behavior change includes its meaningful positive, negative, failure and cancellation tests. Parser and state-machine changes need seeded property tests. Rebuild before running examples. Maintain package READMEs, the API reference and a runnable consumer example with expected output and cleanup. Product error messages and log tests must use fake credentials and verify their redaction.

`pnpm docs:build` renders the API reference under `.build/api` and checks local Markdown links. Component ports intentionally omitted from direct package exports are described through the application interface; they do not imply an installed runtime adapter. API documentation treats broken links and converter warnings as errors. Keep build outputs and local reports outside version control.

Work directly on main with focused commits that keep it reproducibly buildable. Each commit should describe one logical behavior and include the tests that make it reviewable. Do not create development branches or pull requests. Pass applicable local checks before a normal fast-forward push to origin/main, then verify mandatory GitHub Actions on the exact pushed commit. A failed mandatory job blocks further development until a corrective main commit or revert passes. GitHub Actions use main-only pushes and explicitly permitted manual or scheduled entry points, with full immutable action references and read-only permissions. Verify dependency release sources, licenses and compatibility before changing exact pins. Run `pnpm audit --audit-level=high` after dependency changes.

Mermaid diagrams are optional. If a diagram is added, include a pinned renderer and a successful rendering check; the documentation gate rejects unconfigured Mermaid blocks. Keep a complete textual explanation alongside a diagram.

`pnpm test` and coverage select unit, contract and property suites. Integration suites are separate mandatory jobs with disposable external services; `pnpm test:integration:telemetry` requires the real collector and an external evidence path. Missing infrastructure fails the suite instead of skipping it. See the [telemetry reference](packages/telemetry/README.md).

TLS rejection tests require the OpenSSL CLI already present on the supported Ubuntu CI image. They create private keys only in protected temporary directories, trust the test CA only in a short-lived child process, and remove all certificate material after the test. No private certificate/key is versioned.

POSIX JSONL resource-failure tests use the Ubuntu Bash builtin file-size limit and the preinstalled `prlimit` utility in a short-lived child process. They handle `SIGXFSZ` only in that child, verify an actual failed write and rollback of partial data, and restore that child's original limit before V8 emits coverage. The parent and system limits remain unaffected.

`pnpm test:package:messaging` verifies packed portable messaging exports with
an unpatched SDK in a private temporary consumer. The separate NATS matrix
requires verified TLS, scoped accounts, negative transport tests, actual
telemetry export and independent metering. See the
[NATS fixture](packages/messaging/test/fixtures/README.md).

## Private release preparation

The manually dispatched `release.yml` workflow prepares evidence for an existing,
owner-signed exact version tag. Select the `main` branch when dispatching it. The
workflow never creates a tag, changes versions or package privacy, publishes an
npm package, requests an OIDC token or declares a release approved. Ordinary
pushes do not run release preparation.

Before using this workflow, the repository owner must configure the
`release-preparation` environment with at least one required reviewer. Self-review prevention
is an optional stricter owner policy. The workflow independently reads its protection rules
and fails if approval protection is absent or inaccessible. Configure
`ARKENIVA_RELEASE_PUBLIC_KEY` as the owner's ASCII-armored OpenPGP **public** key
and `ARKENIVA_RELEASE_KEY_FINGERPRINT` as the full uppercase primary fingerprint
in repository or environment variables. Never supply a private signing key.
Creating signing identities, tags, environments or publisher configuration is a
separate owner operation.

Preparation accepts only an annotated, valid OpenPGP signature from that exact
primary key, including a signing subkey bound to it. It rejects expired/revoked
signatures, mismatched tag annotations or versions, commits outside
`origin/main`, dirty source and versions that are not identical across all
framework packages. Keys are imported into a disposable private GnuPG directory;
the runner's existing keyring and trust configuration are not used.

For the exact tag commit, the latest attempts of `ci.yml`, `security.yml`,
`compatibility.yml` and `performance.yml` must have completed successfully. Every
job in those attempts must succeed; skipped, missing, cancelled, pending or
failed jobs reject preparation. Workflow and job results are read with bounded,
complete pagination. A previous green run cannot conceal a newer failed run.
The same checks run again after building. Missing permission to read the required
API evidence fails closed.

The job verifies the workspace and packed examples, captures clean commit-bound
SPDX inventories, audits dependencies and rebuilds/inspects the actual private
package archives and their checksums. Private artifacts include the selected
commit and workflow-attempt receipts and are retained for 14 days. These are
build and source-binding evidence, not npm provenance attestations or proof of
publication. The existing package inspection report deliberately retains
`publicationAuthorized: false`.

A green preparation job is insufficient for publication: calibrated performance
acceptance, complete required compatibility and security evidence, the public
API review, release notes and external federation gates still apply. Short
performance smoke jobs do not replace full measurements or owner-deferred
repetitions and soak tests. A future publication change requires separate owner
authorization, approved scope/publisher identity, an explicitly reviewed package
privacy/version transition and a protected publishing environment. Only that
separate publishing job should receive the narrowly scoped OIDC permissions
needed by trusted npm publishing; no npm credential belongs in normal tests.
