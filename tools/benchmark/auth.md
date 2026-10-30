<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native JOSE bearer-verification comparison

Build the workspace and choose a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation auth --verify /private/auth-verification
```

Four isolated profiles compare pinned JOSE with the actual public security plugin,
including installed standard/detailed SDK profiles. The parent owns a real signed
JWT/JWKS issuer on an ephemeral HTTP loopback listener, explicitly allowed only
in test configuration. Both paths verify RS256 signatures, exact issuer/audience,
expiry, scope membership and the signed tenant claim. Invalid signatures, wrong
issuer/audience and expired tokens must fail. The independent issuer must observe
one actual JWKS request per isolated profile.

The native baseline uses JOSE verification and a fixed valid-claim projection.
It omits framework complete hostile-claim normalization, provenance tracking,
tenant authority, bounded transport, cancellation and lifecycle policy. Separate
public checks reject copied identity/tenant objects and revoke tenant provenance
on shutdown. Signed arbitrary assurance/ACR claims do not grant MFA without the
configured independent assurance resolver. No TypeScript shape establishes trust.

`--verify` records functional evidence without samples. `--smoke` measures at
least 1000 actual `verifyBearer` completions after 100 warmups per profile, using
the warmed JWKS cache and concurrency one. Actual successful/rejected verifier
counters must match completed calls. Child CPU and sampled memory include the
measurement machinery; issuer CPU is not measured. Reports exclude tokens and
claims.

This module deliberately adds no synthetic per-verification SDK instruments.
Installed SDK profiles report zero instruments/spans for this scenario, and the
collector receives zero bodies; exporter delivery is a separate workload.

Reports retain `releaseGate: false`. This test-only issuer establishes no
production insecure-transport permission, session/MFA assurance, key-rotation
acceptance, dedicated-runner budget, five paired repetitions or one-hour soak
acceptance.
