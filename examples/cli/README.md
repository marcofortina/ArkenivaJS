# CLI project consumer

This example creates a disposable starter outside the source repository, adds the DNS dependency twice, compiles the actual produced TypeScript and starts its real loopback HTTP service. It checks the greeting, source preservation, idempotency and the actual installed CLI executable's help.

```sh
pnpm --filter '@arkenivajs/example-cli...' build
pnpm --filter @arkenivajs/example-cli test
pnpm test:packed:examples --example cli
```

The test links the consumer's already installed core, API, logging and Node declarations into its owned temporary project. The packed variant therefore exercises real packed public packages, without relying on unpublished registry versions or running an installer inside the starter. All temporary files, links and listeners belong to this example and are closed afterward.

For a normal project, run `arkenivajs new my-service`, then install its exact dependencies after those packages are available through the approved publication process. `arkenivajs add dns` adds a manifest dependency only: register `dnsPlugin()` deliberately when your application needs it. See the [CLI reference](../../packages/cli/README.md) for filesystem ownership, locking, cancellation and error behavior.

The starter greeting is intentionally public and bound to loopback. It is not a production authentication or deployment template. No external service, production secret or database is used by this consumer.
