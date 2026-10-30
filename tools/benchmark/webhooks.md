<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Durable webhook signature verification comparison

Build the workspace and use the private environment runner for the
[owned PostgreSQL fixture](../../packages/database-postgres/test/fixtures/README.md).
Both `DATABASE_URL` and the fixture's explicit disposable flag are required.

```sh
pnpm --filter @arkenivajs/benchmark-foundation webhooks --verify /private/webhook-verification
```

Four isolated profiles compare direct Node HMAC-SHA256 with the public webhook
plugin and actual standard/detailed SDK instrumentation. An authenticated owned
loopback bridge supplies a test principal, an ephemeral random external test key
and the actual PostgreSQL atomic nonce store. The child never receives database
credentials. The bridge checks its bearer credential, allowed operations and
nonce namespace at runtime. Other transactional-store operations fail closed.

Native/public signatures must agree on raw body bytes including whitespace and
the final LF. Verification must reject a compact reserialization, accept the
original bytes exactly once and reject replay. Independent SQL readback requires
four persisted nonce rows from eight claim attempts, rather than trusting child
receipts. Reports and SDK exports exclude payload, bearer, key, principal and
tenant values. The parent waits for actual provider work before dropping only
its fresh owned SQL schema and erasing its test key.

This valid-corpus verification does not duplicate the framework's full hostile
input, rotation, clock-window, admission or lifecycle policy in the baseline.
Provider bridge calls add local HTTP overhead shared by both paths. They do not
recommend a production authentication or secret-store deployment. No outbound
delivery, retries, receipt durability or TLS transport performance is measured.

Only `--verify` is supported. It emits no latency or resource samples and keeps
`releaseGate: false`. Sampling, dedicated-runner budgets, five repeated trials
and a one-hour soak remain separate work. Integration tests use actual SQL and
also reject unauthorized bridge access and unsupported namespaces.
