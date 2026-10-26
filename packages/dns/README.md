# Isolated DNS resolution

`@arkenivajs/dns` uses only Node's `node:dns/promises` as its DNS backend.
Each configured profile owns a separate native `Resolver` with its own
`setServers` configuration. The package never calls global `dns.setServers`,
implements a recursive server, changes OS hosts configuration or contacts a
public resolver as an implicit fallback.

```typescript
import { createDnsService } from '@arkenivajs/dns';

const dns = createDnsService({
  resolvers: [{ name: 'lab', servers: ['127.0.0.1:15353'] }],
  defaultResolver: 'lab',
  maxConcurrency: 16,
  timeoutMs: 2000,
});
try {
  const records = await dns.resolve({ hostname: 'internal.test', type: 'A' });
  const local = await dns.lookup('localhost', { family: 4, all: true });
} finally {
  await dns.close();
}
```

The server in this example must be an approved resolver. The
[executable DNS example](../../examples/dns/README.md) starts and closes its own
disposable loopback authority, with an existing third-party DNS packet codec.
It needs no production DNS, system configuration changes or credentials.

| Method                                        | Meaning                                                               |
| --------------------------------------------- | --------------------------------------------------------------------- |
| `resolve({hostname,type,resolver?},options?)` | Network DNS through one explicitly configured profile                 |
| `lookup(hostname,{family?,all?}?,options?)`   | OS `getaddrinfo`/hosts semantics, independent of profile server lists |
| `reverse(ip,{resolver?}?,options?)`           | Native PTR lookup for a strict IPv4/IPv6 literal                      |
| `getResolvers()`                              | Frozen safe profile names; no internal server addresses               |
| `close(options?)`                             | Idempotently stop new work and cancel owned native resolvers          |

Supported records are `A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `SOA`, `SRV`, `TXT`,
`CAA` and `NAPTR`. A/AAAA results contain `{address,ttlSeconds?}`; TTL is present
only if supplied by Node and remains in seconds. Names and structured records use
the public `DnsRecordMap`. TXT preserves the segments of each separate record.
CAA returns `{critical,tag,value}`; NAPTR regexp text remains data and is never
executed. No caching or TTL persistence is added by this adapter. Upstream
resolvers and OS facilities can have their own caching behavior.

Settings require a nonempty list of up to 64 profiles, with unique safe names
matching `[a-z][a-z0-9-]{0,62}`. Each has `1..16` literal DNS server endpoints,
optionally with ports. Hostname server discovery and scoped IPv6 zone IDs are
unsupported. `defaultResolver` selects a configured name and otherwise defaults
to the first explicit profile. `maxConcurrency` accepts integers `1..1024`;
`timeoutMs` accepts `1..120000`. Node resolver attempts are bounded to one try.
Settings are immutable after capture and all fields are validated before native
allocation; null, unknown properties, accessors and invalid profiles fail with
`EK_DNS_CONFIG`.

Queries apply native IDNA conversion, DNS label/domain length checks and safe
syntax validation. Fully qualified trailing dots and SRV/TXT underscore labels
are accepted; URL syntax, whitespace and malformed labels are rejected. Reverse
lookup requires a strict IP literal. `lookup` accepts family `0 | 4 | 6` and a
boolean `all`; its public result is always a readonly array, even when Node
returns one address. It intentionally does not apply a profile's server list.

Responses remain untrusted. The adapter validates native DTO shape, address
families, numeric ranges and finite output sizes before returning frozen data.
It accepts a matching optional native record-type tag without exposing SDK-only
metadata. Limits are 1024 records, 256 segments per TXT record and 1 MiB of
normalized response data. No answer grants authentication or proves safety
against SSRF, DNS rebinding or a malicious authority. Destination safety still
belongs in the connection/proxy policy. DNSSEC, DoH, DoT and authoritative hosting
are excluded.

NXDOMAIN/NODATA use `EK_DNS_NOT_FOUND`; transient failure or admission saturation
uses `EK_DNS_TEMPORARY`; native or operation deadline expiry uses
`EK_DNS_TIMEOUT`. Invalid input uses `EK_DNS_CONFIG`. Public errors contain no
raw hostname, resolver endpoint, upstream error message or abort reason.

Per-call `timeoutMs` is positive and can only shorten the deployment deadline.
`signal` must be a native AbortSignal. A rejected/canceled public promise does
not imply the underlying native operation stopped. Individual cancellation never
calls a shared profile's `cancel()`, which would also affect other queries.
Physical admission remains occupied until the actual native promise settles;
there is no unbounded pending queue. `close` stops acceptance immediately,
rejects pending public operations and cancels only this service's owned native
resolvers. OS lookups may complete later. Stopped handles use
`EK_RESOURCE_CLOSED`.

For application ownership, install `dnsPlugin(settings)` and resolve
`DNS_CAPABILITY` as `DnsService`. Existing logging/telemetry owners are optional
and resolved through the existing scoped support SPI; no implicit SDK is loaded.
Logging emits only fixed operation metadata and safe configured profile names.
It never emits query names, addresses or record contents. Failures of synchronous
or asynchronous observers cannot replace results or repeat native operations.

The telemetry adapter uses `dns.operation.count`, `dns.response.records`,
`dns.duration.ms`, `dns.inflight` and `dns.observation.dropped`. Duration is the
public-promise latency in milliseconds; the in-flight gauge counts native
operations still outstanding, including work after caller timeout. No DNS wire
bytes or per-request CPU/RAM attribution is invented. Correlation belongs to the
installed logger/OTel context; DNS data never establishes tenant provenance.

Namespaced labels are `dns.operation`, `dns.type`, `dns.resolver` and
`dns.outcome`. Operation/type/outcome values have fixed SDK catalogs. Configure
the existing telemetry owner's explicit profile-name whitelist before startup:

```typescript
telemetryPlugin({ labelValues: { 'dns.resolver': ['lab', 'os'] } });
```

`os` denotes lookup semantics. Unapproved label values fail closed under the SDK
policy; failed observations increment the bounded drop counter when possible,
instead of claiming complete metric export. Raw hostnames are never permitted
metric labels. Use actual verified request context separately when applicable.

Tests include real loopback A/AAAA/all structured records, TXT segments, reverse
lookup, contradictory named servers, OS-hosts differences, IDNA, failure replies,
deadline/cancellation, shutdown, native work retention and observer privacy.
Performance measurements and remote compatibility are separate release gates.
