<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Signed webhook delivery and verification

`@arkenivajs/webhooks` provides native HMAC-SHA256 signatures, atomic replay claims and bounded delivery through the existing HTTP client. It opens no inbound route. Importing it performs no DNS, network, secret-provider or database operation. Install only the optional adapters your application uses.

Register `webhooksPlugin(settings)` before `app.start()`, then resolve `WEBHOOKS_CAPABILITY` as `WebhookService`. The service has four methods:

```typescript
const signature = await webhooks.sign(rawBody, 'provider/current-key', context, {
  timeoutMs: 2000,
});
const verified = await webhooks.verify(rawBody, signature, context, { timeoutMs: 2000 });
const receipt = await webhooks.send('partner', {
  id: 'event-one',
  type: 'order.created',
  payload: {},
});
const event = webhooks.parseEvent(rawBody);
```

`context` contains `destinationId`, `eventId`, `timestamp`, `nonce` and `keyId`. A signature contains `algorithm:'hmac-sha256'`, the same key/timestamp/nonce, and a canonical 43-character base64url MAC. `parseEvent` validates bounded native JSON and returns immutable `{id,type,payload}` data. Parsing alone provides no authenticity, tenant or schema guarantee. `sign`/`verify` preserve exact received bytes, including whitespace, binary content and encoding; they never parse and reserialize a body before verifying it.

## Providers and trusted policy

Settings require a fixed `destinations` catalog, external `secretProvider`, `nonceStore`, runtime `authority` and positive finite `policy`. Each profile has `name`, HTTPS `origin`, `hmacKeyRef`, explicit `allowedCidrs`, `maxRetries` and positive `timeoutMs`. Origins are scheme/host/port roots; credentials, fragments, queries, paths and dynamic URLs are rejected. Names are lowercase identifiers. The catalog has at most 16 entries and each CIDR list 1–32 entries.

The authority is an extension of `TrustedSecurityAuthority`. Every sign, verify and send calls its `require` method with the operation and typed `WebhookAuthorizationContext`: validated `destinationId`, event-ID hint and optional key-ID hint. It must authenticate/authorize against server-owned state and return the canonical subject/tenant. These hints are not identity proof. A body, header, copied object, asserted tenant or successful cryptographic check cannot substitute for the application's authentication and destination policy. Provider failures deny the operation.

An inbound background receiver normally authorizes its own tenant-bound service principal independently of the sender's request. Use the same canonical receiver `(issuer,subject,tenant)` across replicas; nonce ownership includes that tuple, destination and nonce. A different authorized receiver owner has a separate replay domain. The application's policy must prevent unapproved accounts from selecting a receiver owner or destination. Sender and receiver principals may differ while resolving to the same approved tenant; that tenant is part of the MAC framing. No tenant means a separately signed global scope, which must itself be explicitly authorized.

The secret provider must independently assure key entropy, provenance, access and immutable version IDs. At least 32 bytes and at most 4096 are accepted. Keys are copied only for native HMAC work; owned copies are erased, while provider-owned buffers remain provider-owned. Keys, MACs, nonces, payloads and bearer tokens are never logged or stored as replay data. No production in-memory fallback or per-pod ephemeral signing key exists. Test-only storage/providers and cleartext destinations are rejected outside `environment:'test'`; cleartext tests are restricted to configured literal loopback/localhost origins.

`nonceStore` requires the complete `SecurityTransactionalStore`, including an atomic shared `claimOnce`. Verification checks authority, time, key and MAC before claiming. Exactly one contender can receive a verified result. Storage failure never produces a verified result; interrupted claims can have an explicitly unknown completion state. Store only opaque nonce digests and expiry. Retain through the final accepted timestamp window, at most approximately ten minutes from claim; the five-minute past/future clock tolerance uses server time. Request-controlled clock overrides are unavailable. Timestamp strings must be canonical UTC ISO instants with milliseconds.

## Version 1 signature profile

Compute UTF-8 compact JSON for this **ordered array of strings**, append one LF byte, then append the **unchanged raw HTTP body bytes**:

```text
["arkenivajs.webhooks.v1", verifiedTenantIdOrEmpty, destinationId, eventId, timestamp, nonce, keyId]
LF
raw body bytes
```

Use native HMAC-SHA256 under the selected external key and unpadded canonical base64url encoding. Metadata strings preserve their exact Unicode content, disallow control/format characters and ill-formed UTF-16, and are JSON-escaped. No JSON canonicalization of the body occurs. Verification validates the digest encoding/length before native constant-time comparison. A nonce is 22–128 base64url characters; outbound delivery uses 24 random bytes.

`keyId` must equal the provider's immutable `keyVersion`. Signing uses only a profile's current `hmacKeyRef`. To retain old verification versions, configure `verificationKeys:[{keyId,hmacKeyRef,expiresAt}]`, at most 16 distinct entries. Each maps one version to a provider reference and explicit rotation-window expiry. Expired/unknown/mismatched versions fail; an unavailable old provider does not fall back to another key. Key rotation does not permit a consumed nonce to be reused.

Outbound POST uses `Content-Type: application/json`, `arkeniva-webhook-context` containing base64url UTF-8 compact JSON of the five context properties, and `arkeniva-webhook-signature` containing `v1,` followed by the MAC. Decode the context, construct the four signature metadata properties plus `algorithm`/MAC, then call `verify` with the original body. The original sender identity is not inferred from these headers; MAC verification and application policy establish the approved event provenance.

## Delivery, SSRF and idempotency

Delivery uses only the named configured origin. DNS answers must all match its CIDRs at connection time; literal IPs are also checked. The HTTP client enforces TLS certificate/hostname verification and disallows private/reserved production destinations. Redirects are returned as rejected deliveries without following Location. Incoming headers, cookies and bearer tokens are never forwarded. Payload URLs are ordinary data and are not fetched.

`maxRetries` is 0–2. A nonzero value also requires `idempotent:true`, meaning the destination's documented contract guarantees event-ID idempotency. This is an application prerequisite, not something HTTP or an arbitrary TypeScript boolean can prove. The default behavior sends once. Eligible transient 429/5xx or unknown transport outcomes may be retried with bounded jitter and the same bounded event bytes. Each attempt has a fresh signed nonce/timestamp and a stable `Idempotency-Key` derived from tenant, destination and event ID. No automatic retry follows a redirect or ordinary 4xx.

Receipts return destination/event IDs, `attemptCount` and `status:'accepted'|'rejected'|'unknown'`. Accepted means a 2xx HTTP acknowledgement, including 202; it does not prove processing or durable outbox storage. Lost acknowledgements and transport ambiguity return unknown. Abort/timeout after a possible side effect raises the common error with `details.outcome:'unknown'`. Neither a rejected response nor cancellation promises business rollback. Persistence/outbox and receiver business idempotency remain application responsibilities.

## Resource and observation limits

`policy.maxConcurrent` is 1–16; `timeoutMs` is 1–120000. Input defaults to 1 MiB, maximum 8 MiB; response buffering defaults to 64 KiB, maximum 1 MiB. JSON is limited to depth 32 and 4096 nodes, checked before serialization. Options may tighten the operation deadline and add a genuine native AbortSignal. Zero, null, unknown fields, shared-memory input and structural cancellation objects are rejected. Input bytes/configuration are captured before provider awaits.

There is no operation admission queue. Private provider work retains capacity until it settles. Native OS DNS cannot be preempted; an independently bounded task set retains those resolutions after a public timeout, contributes conservatively to new admission and drains during shutdown. Saturation fails immediately. The service rejects calls before application READY and after shutdown. Owned HTTP agents close through core drain/close; uncooperative providers can cause a reported shutdown deadline failure rather than a false completion claim.

Optional Pino/OTel signals contain only bounded operation/outcome, actual payload bytes, attempt counts, verification failures and elapsed time. These quantities are content measurements, not TLS/network wire billing or monetary cost. Native HTTP transport measurements remain a separate layer.

Errors include `EK_WEBHOOK_SIGNATURE`, `EK_WEBHOOK_REPLAY`, `EK_WEBHOOK_DELIVERY`, common configuration/authentication/capacity/cancellation errors and safe messages. Internal causes, keys, endpoint credentials and client data do not cross the error boundary.

See [the executable consumer](../../examples/webhooks/README.md) and [the durable PostgreSQL receiver guide](../../examples/postgres/webhooks.md). Functional tests include real HTTP/HTTPS and signed OIDC; the replay matrix uses PostgreSQL 17/18 with independent pools on Node 22/24/26. Comparative performance, soak and current-head remote release gates remain required before a production-ready release claim.
