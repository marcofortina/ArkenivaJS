# ArkenivaJS

Modular ESM libraries for Node.js and TypeScript backend services. Packages expose typed contracts and explicit integrations without installing unrelated database drivers.

This workspace is private and under development. No npm packages have been published. Use Node.js 24 for development; supported runtime tests also cover Node.js 22 and 26.

Install the pinned package manager and verify the workspace:

```sh
npm install --global corepack@0.36.0
corepack enable
pnpm install --frozen-lockfile
pnpm verify
```

The verification command checks formatting, lint, an explicit build, types, unit and contract tests, coverage and an ESM smoke. The lockfile records exact dependency resolution.

Read the [API reference](docs/api.md) and run the [configuration example](examples/configuration/README.md) for a complete introduction to typed configuration and isolated lifecycle management.

The [observability example](examples/observability/README.md) demonstrates contextual JSON logging, safe errors, native process snapshots and resource cleanup without external services.
