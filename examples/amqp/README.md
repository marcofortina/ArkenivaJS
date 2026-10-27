<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# RabbitMQ AMQPS example

This executable TypeScript application installs only the explicit native AMQP
plugin. It publishes binary bytes with signed int64, timestamp and binary header
values, waits for a native broker confirm, manually acknowledges the delivery and
checks an unroutable mandatory publication. Tenant wire metadata stays untrusted.

Use the Node and pnpm versions pinned in the root manifest. Build the workspace
before running this example. Run Docker only inside the integration VM or a
disposable CI runner; OpenSSL and Python 3 are required there. The pinned official
RabbitMQ image creates isolated ephemeral credentials, an owned private volume,
verified AMQPS and separate configure/use/denied permissions. No production broker
or production credentials are required.

```sh
python3 -B packages/messaging-amqp/test/fixtures/prepare.py
```

The command prints only the private metadata path. Keep that directory and its
files outside the checkout with their restrictive permissions. Set the absolute
path in the test environment; the checked-in `.env.example` is only an inventory
and does not load environment variables:

```sh
export ARKENIVA_AMQP_FIXTURE=/private/owned-fixture/runtime.json
pnpm --filter @arkenivajs/example-amqp build
pnpm --filter @arkenivajs/example-amqp start
pnpm --filter @arkenivajs/example-amqp test:integration
pnpm test:packed:examples --integration amqp
```

Expected CLI output is
`{"status":"confirmed","returnedStatus":"unroutable","deliveredBytes":3}`.
The integration suite uses compiled public packages and includes actual native
logging/OTLP observations. The independent verifier installs reviewed package
archives and their exact required compatibility diff; see the
[native codec installation requirements](../../packages/messaging-amqp/README.md).

For local laptop development, prepare the fixture in the owned VM and use
host-key-verified SSH forwarding for its loopback AMQPS port. Copy only private
runtime metadata and the public CA to a private local directory, adjusting the
endpoint to the owned forward. The restart controller in that private metadata
must execute the fixture's `control.py restart` inside the same VM. Never install
Docker or the broker on the laptop for these tests.

```sh
pnpm --filter @arkenivajs/messaging-amqp test:integration
python3 -B packages/messaging-amqp/test/fixtures/control.py teardown "$ARKENIVA_AMQP_FIXTURE"
```

Run teardown inside the fixture VM or CI runner using its original metadata. It
verifies container, network and volume ownership before removing them, then
removes private fixture files. Close owned SSH forwards separately.

The fixture uses explicit administrator provisioning and a resolver marked
`test-only`; production rejects that resolver. A deployed application must use
its external secret authority, a trusted static routing catalog and least
privilege broker credentials, with pre-provisioned topology by default. Missing
CA trust, denied provisioning, unknown routes, malformed headers and size limits
are explicit errors. Uncertain publications are never automatically retried;
business deduplication and broker dead-letter/retry policy remain explicit.
