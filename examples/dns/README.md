# Native DNS and OS lookup

This example starts an owned UDP authority on an ephemeral IPv4 loopback port,
uses `@arkenivajs/dns` through its public package, then closes the resolver and
fixture. The `dns-packet@5.6.1` development fixture owns wire encoding/decoding;
the product client uses native `node:dns/promises`. No public DNS, production
credentials, global resolver changes or hosts-file edits are required.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-dns start
pnpm --filter @arkenivajs/example-dns test
pnpm test:packed:examples --example dns
```

Expected CLI output contains only status/count data:

```json
{
  "aRecords": 1,
  "srvRecords": 1,
  "txtRecords": 2,
  "firstTxtSegments": 2,
  "ttlObserved": true,
  "osLookupDistinct": true
}
```

`resolve` queries the configured profile. `lookup('127.0.0.1')` uses Node's OS
lookup semantics and does not contact that profile. The tests also query
`localhost` through both APIs: the synthetic authority and `/etc/hosts` give
intentionally different answers without changing either system configuration.

The live suite covers all 11 approved record types, actual IPv4/IPv6 PTR queries,
IDNA, TXT segment preservation, observed TTL, two contradictory profile servers,
independent service lifetime, NXDOMAIN/NODATA/SERVFAIL, timeout and cancellation
that preserves another query on the same Resolver. Every socket/timer is owned
by the fixture and closed in `finally`. The fixture is a test authority and never
forwards requests or acts as a production recursive resolver.

The packed verifier recompiles this project's source/test code and runs the
same live suite against installed package archives. No framework source alias or
test-only product provider is used. See the
[DNS reference](../../packages/dns/README.md) for resource, privacy, observability
and destination-safety boundaries. Performance and remote CI remain release gates.
