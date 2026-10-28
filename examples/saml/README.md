# SAML browser transfer over verified HTTPS

Run `pnpm --filter @arkenivajs/example-saml build` and `pnpm --filter @arkenivajs/example-saml test` from the workspace root.

The executable example creates two owned HTTPS endpoints with temporary OpenSSL certificates: an SP and a synthetic IdP backed by the actual Node-SAML library. It exercises signed Redirect requests and signed POST forms, a doubly signed response, cookie-bound correlation, a foreign-cookie rejection and replay rejection. Every HTTPS request validates its configured CA and hostname. Temporary credentials and listeners are removed afterwards.

`browserTransfer` renders the public binding discriminant: a 303 redirect or an escaped POST form with an explicit Continue button. Its CSP permits submission only to the pinned IdP origin; it uses no inline script. Responses disable caching and referrers. A separate test verifies HTML attribute escaping.

The synthetic IdP and memory state in the test fixture are explicitly test-only. Deployments require shared durable replay state and shared browser transactions. Bind an opaque Secure, HttpOnly browser cookie to the server-side request ID; retrieve that expected ID independently of the posted form, compare RelayState and atomically consume the transaction. The callback must enforce method, content type, body bounds and one value per field. A cross-site POST requires the deployment's deliberate SameSite policy and browser compatibility checks.

Successful verification yields an upstream identity, not a local session or tenant authorization. The application must resolve the verified issuer and subject through its trusted account mapping, authorize tenant membership and then create a local session. The PostgreSQL example's SAML integration tests demonstrate the SQL mapping and independent authorization required for logout. Signed `tenant_id` attributes alone never grant a canonical tenant.

The HTTPS driver performs the transfer through actual sockets and form fields; it does not claim a browser-engine compatibility run or a production IdP certification.
