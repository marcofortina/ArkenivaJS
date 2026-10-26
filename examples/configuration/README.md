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

## Configured capability ownership

```sh
pnpm --filter @arkenivajs/example-configuration capabilities
```

[src/capabilities.ts](src/capabilities.ts) installs an application-owned counter
through an explicit symbol and the normal plugin DAG. Its provider declares the
configuration dependency; a consumer resolves the counter after an asynchronous
initialization step. The same `resolve<CounterService>(COUNTER_CAPABILITY)` call
works after startup. A distinct symbol with the same description remains absent.

The program prints initialization value `2`, runtime value `4`, and the observed
`EK_LIFECYCLE_STATE`/`EK_RESOURCE_CLOSED` codes after shutdown. `tryResolve` returns
`undefined` for a missing key, while lifecycle/dependency failures throw. Started
dependencies remain available to admitted drain work until their owner releases
them. Lookup never initializes an undeclared adapter. The example and CLI run
through packed public libraries in the workspace example checks.
