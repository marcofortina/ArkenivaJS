# Common data validation

`@arkenivajs/data-validation` provides synchronous, optional format validation.
It uses `validator@13.15.35`, Node's WHATWG URL/IDNA and IP syntax APIs,
`ipaddr.js@2.5.0`, the framework's identifier facade, and
`ajv@8.20.0` with `ajv-formats@3.0.1`. It performs no DNS, mailbox or network I/O.

```typescript
import { createValidationService } from '@arkenivajs/data-validation';

const validation = createValidationService({
  schemas: {
    customer: {
      type: 'object',
      additionalProperties: false,
      required: ['id'],
      properties: { id: { type: 'integer' } },
    },
  },
  policy: { maxConcurrent: 1, timeoutMs: 1000, maxInputBytes: 65536 },
});

const email = validation.email('User@EXAMPLE.ORG');
if (email.valid) console.log(email.value); // User@example.org
validation.assertSchema({ id: 7 }, 'customer');
```

| Method                         | Behavior                                                                                            |
| ------------------------------ | --------------------------------------------------------------------------------------------------- |
| `email(value, options?)`       | Preserve local-part case; lowercase IDNA domain; no trimming or provider-specific mailbox rewriting |
| `url(value, policy)`           | Absolute HTTP(S) URL, explicit schemes and exact normalized hostname allowlist                      |
| `ip(value, policy?)`           | Strict dotted-decimal IPv4 or IPv6; native canonical output                                         |
| `uuid(value, version?)`        | Same canonical lowercase UUIDv4/v7 policy as `data-identifiers`                                     |
| `assertSchema(data, schemaId)` | Check a bounded snapshot using a startup-compiled JSON Schema catalog                               |

Successful format results are `{valid:true,value,errors:[]}`; invalid data produces
`{valid:false,errors:[{path,code,message}]}` without copying input into diagnostics.
Invalid operation policies throw `EK_VALIDATION_POLICY`. Schema assertion failure
throws `EK_VALIDATION_INVALID`; unknown schema IDs use `EK_VALIDATION_POLICY`.
Invalid deployment settings use `EK_CONFIG_INVALID`. Unknown fields, accessors,
null options and invalid limits fail explicitly. Outputs are never silently truncated.

Email defaults to ASCII local parts/domains and a 254-byte maximum; set
`allowInternationalized:true` to permit internationalized input, including EAI local
parts and IDNA domains. `maxLength` accepts integers `1..254`, measured on both input
and normalized UTF-8 output. Mailbox syntax never proves ownership or deliverability.

IP versions default to either 4 or 6; IPv4-mapped IPv6 requires
`allowMappedIPv4:true` and remains an IPv6 result. Zone IDs, CIDRs, brackets, octal,
hexadecimal and shortened IPv4 forms are rejected. IP validation itself permits
private addresses; URL network policy is a separate decision.

URL schemes are a nonempty distinct selection of `http:` and `https:`. Credentials,
control characters, backslashes, implicit schemes and trailing-dot hosts are
rejected. `allowedHosts`, when present, contains `1..256` exact hostnames, with
IDNA and case normalization; wildcards, ports and duplicate normalized entries
fail. Keep this policy in trusted application configuration, never request data.
The contract supplies it per call, so hosts are validated before parsing that
call's input. Host matching is exact, without implicit subdomain permission.

`denyPrivateNetworks` defaults to true. Literal non-unicast addresses, including
mapped private IPv4, and recognizable local names are rejected. A DNS name can
still resolve or rebind to a private address: this API does not resolve it.
Connection-time destination checks, redirect controls and egress policy remain
mandatory for clients/proxies. URL validity alone is never an SSRF safety result.

The required runtime policy accepts `maxConcurrent:1..1024` and
`timeoutMs:1..120000`. Input and successful text/URL output limits default to
65536 UTF-8 bytes and accept integers `1..8388608`. Reentrant work has finite
admission with no queue. Data snapshots additionally allow at most 4096 nodes and
32 nested levels, reject cycles, non-JSON values, accessors, foreign prototypes,
sparse arrays, symbol properties and dangerous object keys. JSON byte accounting
includes escaping and structure. The caller's data is not mutated or coerced.
Reserved keys are `__proto__`, `constructor`, `prototype`, `valueOf` and `toString`;
the last two prevent method shadowing in the upstream JSON equality helper.

The catalog accepts up to 128 schemas, with a cumulative 256 KiB snapshot limit
and the same structural bounds. It supports strict JSON Schema draft-07 and the
installed standard formats, with local fragment references; remote references,
asynchronous schemas and unknown keywords fail before use. Catalog changes after
construction do not alter the compiled validators. Defaults and property removal
are disabled, as is type coercion.

Schemas are trusted deployment code. Review their regular expressions and
computational complexity, as required by [Ajv's security model](https://ajv.js.org/security.html).
The synchronous API checks elapsed time before returning; it cannot preempt an
executing JavaScript regular expression. It must not compile user-submitted schemas
or serve as a sandbox for arbitrary validation programs. Bound external request
data before calling it. No schema content, payload, email or URL is logged.

For application ownership, register `dataValidationPlugin(settings)` and resolve
`VALIDATION_CAPABILITY` as `ValidationService`. The pure factory needs no other
plugins; application resolution is optional. Stopping one application invalidates
its handle with `EK_RESOURCE_CLOSED`, independently of other applications.

The [utilities example](../../examples/utilities/README.md) executes public imports
and is recompiled/tested against packed artifacts. Tests cover IDNA/EAI, IP mapping,
native URL normalization, literal private destinations, schema immutability,
pollution, limits, malformed policies and isolated lifecycle. Performance and
remote compatibility evidence are separate release gates.
