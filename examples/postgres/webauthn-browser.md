# Controlled WebAuthn browser acceptance

This suite connects `@simplewebauthn/browser` **14.0.0** in a real Chromium page to
the public `createWebAuthnService` API, actual signed OIDC fixture identities and
the [durable PostgreSQL reference](webauthn-state.md). The browser SDK is an exact
development dependency of this example; server packages retain their independent
runtime dependency graph. Its [MIT notice](THIRD_PARTY_NOTICES.md) remains applicable.

## Disposable browser and database

Use Node 22.23.4, 24.22.1 or 26.12.1, pinned pnpm and the
[disposable PostgreSQL TLS fixture](README.md). Supply `DATABASE_URL` privately and
set `ARKENIVA_POSTGRES_DISPOSABLE=1`. The browser suite refuses missing authorization
or service configuration instead of skipping tests.

Run the pinned browser fixture **inside an isolated VM or CI runner**:

```sh
docker compose -p arkenivajs-webauthn-browser \
  -f examples/postgres/test/fixtures/browser/compose.yaml up -d --wait --wait-timeout 40
```

The fixture uses the official Playwright 1.64.0 Noble image by immutable digest,
with Chromium 156, bounded memory/CPU/processes, a read-only filesystem and a
temporary browser profile. CDP binds only `127.0.0.1:19222`. Chromium's test-only
`--no-sandbox` mode operates inside this disposable container/VM, visiting only the
owned loopback frontend. No physical authenticator, biometric, real account or
user browser profile is involved. See the
[upstream container documentation](https://playwright.dev/docs/docker).

For a separate VM, use an authenticated SSH tunnel from the workspace machine.
`INTEGRATION_VM` is the configured SSH destination of that owned VM:

```sh
ssh -N -L 127.0.0.1:19222:127.0.0.1:19222 \
  -R 127.0.0.1:19377:127.0.0.1:19377 "$INTEGRATION_VM"
```

The reverse tunnel lets Chromium reach the owned frontend while preserving its
`http://localhost:19377` origin. This uses the browser's explicit localhost secure
context exception. Production RP/origin/HTTPS policies remain independently configured.

From the workspace root:

```sh
pnpm install --frozen-lockfile
pnpm build
export ARKENIVA_WEBAUTHN_BROWSER_DISPOSABLE=1
export ARKENIVA_WEBAUTHN_BROWSER_URL=http://127.0.0.1:19222
export ARKENIVA_WEBAUTHN_BROWSER_ORIGIN=http://localhost:19377
pnpm --filter @arkenivajs/example-postgres test:browser
pnpm test:packed:examples --browser postgres
```

Run suites sequentially when sharing these fixed loopback ports. The PostgreSQL
CI matrix runs the browser gate on both reviewed server versions and every supported
Node line. Each test owns and closes its page, HTTP listener, private schema and
application pools; fixture shutdown removes the temporary authenticator profile:

```sh
docker compose -p arkenivajs-webauthn-browser \
  -f examples/postgres/test/fixtures/browser/compose.yaml down
```

## Behavior and trust boundaries

The page loads the pinned SDK from the owned HTTP fixture. Backend operations run
in trusted test code with independently authenticated principals. Application login
endpoints must supply their own authenticated sessions, CSRF protection, HTTPS,
authorization policy and single-use evidence consumption.

The suite covers registration, bound authentication, credential listing, passwordless
account mapping after primary-session revocation, management grants consumed once,
credential revocation and invalidation of pending ceremonies. Foreign tenants and
hand-built principals/grants reject. Evidence is consumed once for its exact account,
tenant and session/transaction. A real evidence write followed by an uncertain
acknowledgement rejects and consumes the ceremony.

Native authenticator overrides produce bad UP, bad UV and bogus signatures; each
rejects without a credential state write. Normal browser counters must increase.
Switching the emulator to counterless mode must first reject its counter drop.
The counterless race then explicitly bootstraps the **owned test row** at zero and
configures CDP `signCount: -1`; Chromium produces both zero-counter signatures.
Two independent full service processes consume distinct challenges and reach a
SQL barrier with the same loaded revision. Exactly one durable CAS succeeds; the
other returns `EK_MFA_CREDENTIAL_CONFLICT`. No assertion is automatically retried.
See the [native WebAuthn automation protocol](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/).

The closed parent/child test channel supplies the workers' preauthenticated fixture
context. Public requests cannot use this channel or choose trust configuration.
Browser responses, handles, private keys, credential IDs and evidence are never
printed. The fixture's atomic state tests, performance gates and real deployment
authority review remain independently required.
