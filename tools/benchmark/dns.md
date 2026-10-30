# Controlled DNS comparison

Build the workspace before using the DNS tool. It reuses the example's actual
nonforwarding loopback authority and `dns-packet` codec. No daemon installation,
operating-system DNS change or external DNS query is required.

```sh
pnpm --filter @arkenivajs/benchmark-foundation dns --verify /private/new-dns-verification
```

The output directory must be new, absolute and outside the checkout, with an
existing parent. Four isolated profiles compare native `node:dns/promises` with
the public service, standard telemetry and detailed telemetry. Verification
checks A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA and NAPTR results, native OS
lookup of a literal address, reverse lookup and configured safe resolver names.
TTLs and TXT segment boundaries are retained. DNS answers remain untrusted data;
they provide no authorization or SSRF guarantee.

`--verify` reports `measured:false`. `--smoke` instead performs 20 warmup calls and
at least 100 samples per operation, awaiting every response with concurrency one.
Network queries use a fresh deterministic name sequence in every profile to
reduce cache effects. Reverse samples use reserved documentation addresses only
as DNS data. The lookup scenario uses a literal loopback address and does not
test external OS resolver latency. Startup and shutdown are outside timing.

Reports contain process-aggregate CPU/memory/event-loop/GC observations and
latency quantiles. Actual diagnostic exports are checked for drops/failures and
query/server input leakage. `protocol-observation.json` separately counts actual
received packets and confirms that no query was forwarded. Each child also
checks its global Node resolver settings before completion and exit.

These short runs always set `releaseGate:false`. They are controlled protocol
and measurement-tool checks, not Internet DNS performance, confidence intervals,
production overhead budgets, DNSSEC, repeated campaigns or soak acceptance.
