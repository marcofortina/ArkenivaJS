# SAML account mapping and distributed replay

The SAML integration suites use the actual PostgreSQL security-state provider over verified TLS. Two service owners and two independent Node processes race to consume the same signed response; only one returns an identity.

`test/integration/saml.integration.test.ts` resolves the verified upstream issuer and subject through a parameter-bound SQL account mapping. A current local OIDC identity is independently authenticated and authorized for logout using its canonical tenant and required scope. A submitted SAML tenant attribute never chooses the local tenant. An unauthenticated clone of an otherwise valid identity cannot start logout. A storage failure after replay claims cannot yield an identity or make the response reusable.

Run the disposable PostgreSQL fixture through the project's integration tooling, then execute `node --test dist-test/integration/saml.integration.test.js dist-test/integration/saml-process.integration.test.js`. The fixture requires `ARKENIVA_POSTGRES_DISPOSABLE` and uses its own schema; it must never target an existing application database. Database credentials and temporary signing keys are not printed.

The [browser transfer example](../saml/README.md) demonstrates actual HTTPS Redirect and POST traffic. Browser cookie transactions and local application session creation remain application responsibilities; the SAML verification result alone is not a session or tenant authorization.
