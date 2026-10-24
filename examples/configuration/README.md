# Strict configuration example

Prerequisites: Node.js 24 and the pinned workspace package manager. No external services or secrets are required. From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-configuration start
ARKENIVAJS_GREETING='Hello from environment' pnpm --filter @arkenivajs/example-configuration start
pnpm --filter @arkenivajs/example-configuration test
```

The first run prints `{"greeting":"Hello from YAML"}`; the second prints the environment greeting. The example creates and closes an isolated application each time. An empty greeting or an unknown `ARKENIVAJS_*` field fails with `EK_CONFIG_INVALID` and a sanitized JSON envelope.

Applied overrides also write bounded audit JSON to standard error, containing their source and top-level key count. The greeting's value and its field name are excluded from those events. Supply `onDiagnostic` to the loader when routing these events into an owned structured logger.

The source imports public workspace package entry points. Read `.env.example` for the optional variable name; loading a local dotenv file is an application decision. Do not put real secrets into YAML or source code. Provider references and secret environment mappings belong in trusted bootstrap configuration.
