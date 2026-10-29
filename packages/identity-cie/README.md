# @arkenivajs/identity-cie

Optional CIE OIDC federation plugin using the existing Italian federation backend,
native JOSE/OpenID Client, application security and external Crypto services.
Register `ciePlugin(settings)` before application startup and resolve `CIE_CAPABILITY`
after readiness. It installs no SPID plugin, listener, route or local session.

The [executable browser transaction example](../../examples/identity-cie/README.md)
uses public imports, a separate CIE first-party cookie, actual HTTPS callbacks and
an independently installed package consumer. The application retains ownership
of local authorization and session creation.

```typescript
import { ciePlugin, CIE_CAPABILITY } from '@arkenivajs/identity-cie';
import type { CieService, ItalianEidPluginSettings } from '@arkenivajs/identity-cie';

export function configuredCie(settings: ItalianEidPluginSettings) {
  return ciePlugin(settings);
}

export function beginCie(service: CieService, profileId: string, issuer: string) {
  return service
    .forProfile(profileId)
    .beginAuthentication({ returnPath: '/private', issuer }, 'cie-l2', { timeoutMs: 5000 });
}

// After application.start():
// const cie = application.resolve<CieService>(CIE_CAPABILITY);
```

Profiles must declare `system: 'cie'` and approved `cie-l1`/`cie-l2`/`cie-l3`
assurance, explicit registration and callback, pinned trust anchors and metadata
destinations, mandatory revocation, approved identity mapping and shared one-use
state. An application hint or a constructed TypeScript object grants no tenant
authority. The actual application's authentication service validates mapping
provenance at runtime. SAML is unavailable in this adapter.

Configure separate external state encryption/MAC, federation signing and response
decryption references. Optional signed/encrypted ID Tokens are allowed only when
explicitly registered; UserInfo is signed and encrypted. Metadata permissions do
not authorize credential-bearing token, UserInfo or JWK endpoints: configure their
exact approved URLs independently. No key material is persisted in state tables.

The public operations are `forProfile`, `beginAuthentication`,
`consumeAuthentication`, `metadata` and `verifyFederationTrust`. Ambiguous profile
or issuer selection, stale or revoked membership, failed persistence, replay and
unverified canonical mapping fail closed. Trusted application policy authorizes
`cie.begin_authentication` and `cie.consume_authentication`; federation assurance
does not create MFA or a local session automatically.

Install logging, security and Crypto plugins explicitly. The optional CIE plugin
borrows those owners and creates independent admission and transport scopes.
Shutdown aborts work and retains ownership through physical completion. Test-only
providers are rejected outside the test environment.

With the existing telemetry plugin installed, CIE emits
`cie.authentication.duration` in seconds for each public begin/consume attempt,
`cie.federation.checks` for public metadata/trust/health/bootstrap attempts and
`cie.failures` for rejected operations. Duration measures one public operation,
not the complete browser ceremony or CPU time. Check outcomes describe current
verification attempts, not network refresh counts or a guarantee of future
availability. Physical work that outlives a caller deadline remains owned by the
runtime. Inspect the selected backend's health independently.

Only closed `cie.operation` and `cie.outcome` dimensions are emitted. Profiles,
tenants, subjects, URLs, attributes, tokens, statements and provider diagnostics
never become labels or log fields. The label catalog cannot be expanded by
configuration. Diagnostic sink failures do not grant access or replay work.

Local technical fixtures do not establish official CIE interoperability,
accreditation, legal compliance or production certification. Deployments require
their own approved registration, current trust material and independent external
acceptance. See the [Italian OIDC profile rules](https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/index.html).
