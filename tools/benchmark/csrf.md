<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# CSRF comparison controls

This initial slice verifies native and framework CSRF request behavior. It does
not implement a benchmark CLI, retain timing samples, or establish a performance
budget. The existing HTTP header comparison continues to disable CSRF.

The PostgreSQL integration test uses the existing signed OIDC authentication,
durable session authority, external test HMAC provider and two owned security
schemas. A public framework endpoint issues the real session-bound CSRF token
before the paired verification controls. Tokens, cookies, identities, HMAC keys
and state bindings remain private fixture data.

Both listeners use the same temporary EC P-256 identity and verified TLS 1.3.
The client trusts only the owned certificate and verifies its hostname. Native
Fastify uses stock cookie, CSRF protection, CSRF tokens and Helmet packages. It
delegates session resolution, authorization, HMAC domain separation and durable
state access to the same providers as the framework. Its positive request runs
both upstream token checks performed by the framework cookie workflow.

Controls verify exact provider boundaries, committed issuance, successful
requests, missing and invalid tokens, cookie mismatch, hostile origins, foreign
tenant sessions, actual primary-session revocation and recovery after denials.
Denied requests cannot increment the protected handler's effect counter.

The native adapter composes this fixed verification workflow. It does not
reimplement token issuance, framework lifecycle, policy updates, cancellation,
provider supervision or public error normalization. Parent provider execution and
fixture setup are not measurements of standalone upstream cryptography.

The test closes both listeners, retires its private TLS fixture and closes the
existing PostgreSQL fixture, which owns the primary/session and CSRF schemas.
Three telemetry profiles, actual rejection metric exports, retained latency and
resource samples, calibrated offered load, five repetitions and the one-hour
soak remain outside this initial functional slice.
