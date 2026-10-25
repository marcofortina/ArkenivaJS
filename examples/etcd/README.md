# etcd configuration and presence consumer

This executable guide uses the [etcd provider](../../packages/database-etcd/README.md)
on an explicitly disposable mTLS endpoint. It stores raw bytes, observes real
put/delete watch events, preserves actual CAS success/contention outcomes and
attaches binary presence data to an explicitly renewed lease. Revocation removes
the presence key. The example closes its iterator, revokes its owned lease,
deletes only random owned keys and stops the application in `finally`.

Prepare the [private certificate/auth fixture](../../packages/database-etcd/test/fixtures/README.md)
inside a dedicated VM or disposable CI runner. After bootstrap and health checks:

```sh
pnpm build
pnpm --filter @arkenivajs/example-etcd test
python3 packages/database-etcd/test/fixtures/run.py /private/runtime/etcd-fixture/environment.json pnpm --filter @arkenivajs/example-etcd test:integration
python3 packages/database-etcd/test/fixtures/run.py /private/runtime/etcd-fixture/environment.json pnpm --filter @arkenivajs/example-etcd start
```

The CLI requires `ARKENIVA_ETCD_DISPOSABLE=1` and `ARKENIVA_ETCD_URL`. Imports and
offline unit tests do not connect. Output contains `firstAccepted=true`,
`secondAccepted=false`, `mode="enabled"`, `version="1"`, `leaseDeleted=true` and
the actual revision as a decimal string. Revisions vary with server history.
The application deliberately encodes JSON as UTF-8, validates decoded fields and
converts bigint metadata to strings; the provider never treats arbitrary bytes as
JSON or silently rounds revisions. Failures print safe JSON without private URLs,
causes or stacks.

In a service, authorize a verified tenant and bind its least-privileged etcd user
to a server-enforced prefix before choosing keys. CAS contention is a normal
false result. A lost write acknowledgment may have an unknown outcome and is not
retried by this example. Watch replay can duplicate events; compaction/queue gaps
require an authorized snapshot rebuild. Lease keepAlive is explicit, and an
expired lease is never silently replaced.
