# HTTP comparison server ownership and equivalence

`http-worker.mjs` starts an isolated loopback server through either the underlying
libraries or the framework's public packages. It is a development fixture and
does not expose an application deployment API. It requires a disposable TLS
PostgreSQL database and a real test OTel collector.

The three routes return the same checked 128-byte JSON body. `/json` is public;
`/authenticated` requires an actual RS256 bearer assertion with the configured
issuer/audience and `orders:read`; `/database` additionally checks the verified
tenant in a parameterized query. Native and framework paths use pool maximum
two, verified TLS, session reset and bounded cursor/result consumption. Native
response validation remains explicit in addition to Fastify serialization.

BASELINE uses Fastify/Ajv/JOSE/Pino/pg directly. FRAMEWORK uses the corresponding
public framework plugins without telemetry or metering plugins. STANDARD and
DETAILED include actual OTel export and verified tenant JSONL metering. Allowed
HTTP route labels are explicit; observer failures cannot count as a successful
measurement. DETAILED also records a V8 CPU profile at 10 ms intervals.

`http-issuer.mjs` owns a temporary loopback OIDC discovery/JWKS server and signs
synthetic credentials. Credentials are never printed or persisted by the
issuer. These fixtures do not change production issuer/TLS policies.

Build the workspace and configure `ARKENIVAJS_OTLP_ENDPOINT` with the disposable
collector before running the real equivalence suite:

```sh
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm --filter @arkenivajs/benchmark-foundation test:integration
```

The suite runs all four modes, checks identical successful bodies, rejects
missing/invalid/expired/wrong-audience tokens and insufficient scope, and executes
the real database query. It checks exact HTTP/span/meter counts, exporter
acknowledgment, zero observation failures, safe output and idempotent cleanup.
Missing infrastructure fails explicitly. Run the issuer and statistical unit
checks without external services using `pnpm --filter @arkenivajs/benchmark-foundation test`.

Server observations include process CPU, sampled RSS/heap and pool/queue state,
event-loop activity and observed GC pauses. They are aggregate process values,
never exact tenant/request allocation. Flush and profile finalization happen
after the measured CPU interval. Failed startup retains both primary and
cleanup causes; normal shutdown closes only owned resources. Raw artifacts
remain private and outside Git.
