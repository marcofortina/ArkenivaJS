<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Verified LDAPS protocol comparison

Build the workspace and use the private metadata emitted by the owned
[OpenLDAP fixture](../../packages/security-ldap/test/fixtures/prepare.py):

```sh
ARKENIVA_LDAP_FIXTURE=/private/ldap/runtime.json \
  pnpm --filter @arkenivajs/benchmark-foundation ldap --verify /private/ldap-verification
```

The fixture uses its owned loopback LDAPS endpoint on port 16389; its healthy
wrong-SAN endpoint on 16390 must reject verification. No host trust-store change
is made. Only private fixture metadata is read; passwords enter child IPC, never
child environment or arguments. Four isolated profiles use direct `ldapts`, the
public LDAP plugin, and actual standard/detailed SDK instrumentation.

Each profile performs a real service bind, projected user lookup, absent-user
and literal filter-injection lookups, then successful and incorrect-password
user binds. Equality filter values are bound through native BER objects. Fresh
service and user connections are never pooled together. Reports and exports
exclude usernames, DNs, passwords, endpoints and trust material.

The valid-corpus baseline uses the same SDK, CA/hostname checks and fresh-client
pattern. Additional framework work includes secret capture, native child process
isolation, IPC, bounded projections, admission and lifecycle. This comparison
does not establish equivalence of every hostile-input policy.

Only `--verify` is supported, with no latency/resource samples and
`releaseGate: false`. Sampling remains rejected until the whole native child
process tree is accounted for. Group traversal, streamed search, STARTTLS,
Microsoft AD staging, performance budgets, five repeated trials and a one-hour
soak are separate scenarios.
