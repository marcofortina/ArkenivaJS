# Tenant-isolated GraphQL with PostgreSQL

This application uses public ArkenivaJS services over PostgreSQL tables, an actual
OIDC authentication service and a certificate-verified HTTPS endpoint. It keeps
business authorization and database ownership in the application. Every customer
lookup and order batch binds `tenant_id` from verified authentication; request
headers, GraphQL arguments and known foreign IDs cannot select another tenant.

From the workspace root, use the supported Node and pinned pnpm versions:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm --filter @arkenivajs/example-graphql-postgres-tenants build
pnpm --filter @arkenivajs/example-graphql-postgres-tenants test
```

The first test rejects unsafe administrator SQL schema identifiers before service
composition. Full integration additionally requires OpenSSL and an independently
owned disposable PostgreSQL database. Supply its verified connection through
`ARKENIVA_POSTGRES_URL` and set `ARKENIVA_POSTGRES_DISPOSABLE=1`. Never disable
certificate or hostname verification or point these tests at production data.
Credentials belong in the environment or a secure deployment provider, not in
source, logs or command arguments. Then run:

```sh
pnpm --filter @arkenivajs/example-graphql-postgres-tenants test:integration
node scripts/check-packed-examples.mjs --integration graphql-postgres-tenants
```

The integration creates a random private schema, two synthetic tenant datasets,
an ephemeral signing issuer and HTTPS listener. It drops only its owned schema
and retires the application, PostgreSQL pools, issuer and temporary TLS files in
cleanup. The second command independently installs framework archives, recompiles
this consumer and runs the same actual database test through public exports.
CI configures both commands for PostgreSQL 17/18 and every supported Node line.
The disposable issuer's loopback exception is explicitly test-only; application
HTTPS requests still verify the fixture CA and hostname.

To embed the application, call `createCustomerExample` from `src/main.ts` with
explicit service, HTTPS, issuer, audience and administrator-selected SQL schema
settings. Set `connectionStringEnv` when using a different secret environment
reference. Await `app.start()` and always await `app.stop()`. Register production
tables separately through your migration process: this factory performs no DDL.
The sample tables are:

```sql
CREATE TABLE customer_data.customers (
  id text NOT NULL, tenant_id text NOT NULL, name text NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE customer_data.orders (
  id text NOT NULL, tenant_id text NOT NULL, customer_id text NOT NULL,
  total numeric(18,2) NOT NULL, PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ON customer_data.orders (tenant_id, customer_id, id);
```

Create the administrator-owned `customer_data` schema before applying these
statements. Grant the runtime role only the required read permissions. Database
row-level security can add a separate defense; the example does not configure it.

With a verified `customers.read` identity, POST `/graphql`:

```json
{
  "query": "query Page($first: Int!) { customers(first:$first) { id name orders(first:2) { id total } } }",
  "variables": { "first": 100 }
}
```

This executes one parent query and one bounded child batch for both 1 and 100
parents. A PostgreSQL row-number window limits each customer's fetched orders.
The loader preserves parent order, returns an empty array for absent orders and
applies each alias's requested size independently. Placeholder names come from
bounded indexes; all customer IDs, tenant IDs and limits remain named bound
values. The SQL schema is captured from startup configuration and never from
request input. Each query receives the request AbortSignal.

The app allows page sizes from 1 to 100 and explicitly configures complexity
5000 for this nested demonstration; other framework limits remain active.
`total` is a decimal string, preserving values beyond JavaScript's safe integer
range. Every nested customer and order field verifies row ownership before its
default property read. Loader caches are request-owned and cannot share tenant
results across requests.

The integration observes native driver dispatch without replacing results. It
checks both tenants with overlapping IDs, 1/100-parent two-query counts, foreign
headers and known foreign IDs, alias limits and exact decimal results. Missing
or insufficient authentication, oversized pages and introspection produce no
business SQL. Untrusted HTTPS clients fail certificate validation. Business
values and bearer tokens stay out of captured logs. These checks establish local
functional evidence; release, coverage and deferred performance/soak gates remain.

See the [GraphQL guide](../../docs/graphql.md) and the simpler
[REST/GraphQL application](../graphql/README.md) for listener and subscription
composition. This read-only example installs no mutation or subscription API.
