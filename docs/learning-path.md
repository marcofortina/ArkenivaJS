# Build and verify an application

The [GraphQL HTTPS project](../examples/graphql/README.md) adds authenticated
queries and scoped mutations beside REST, with field denials and verified tenant
row filters. Its tests also run through independently installed package archives.

Use a supported Node release from `package.json`, the exact pinned pnpm version,
and a frozen dependency installation. Build the workspace before executing
examples. Package installation is explicit: importing core never enables an
HTTP listener, database driver or security service automatically.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm test:docs
pnpm docs:build
```

The built API site opens at `.build/api/index.html`. Each linked project
below has complete source, its own package manifest, expected output, error
handling and cleanup instructions. Development fixture URLs contain private
credentials and belong outside the checkout. Run container services inside a
dedicated VM or disposable CI runner.

Every example includes `.env.example` as a variable inventory. These applications
do not automatically load dotenv files. Keep actual URLs, passwords and key
paths in the documented private fixture environment loader or an approved
external secret provider; the checked-in inventory contains no live credentials.

| Project                                                          | Learn                                                                    | Infrastructure                                                 |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------- |
| [Configuration](../examples/configuration/README.md)             | YAML, environment precedence and immutable validated values              | None                                                           |
| [Utilities](../examples/utilities/README.md)                     | Native UUIDs, format policies and startup-compiled JSON Schema           | None                                                           |
| [Cryptography](../examples/cryptography/README.md)               | External versioned secrets, authenticated envelopes, MACs and signatures | Disposable loopback HTTPS and OpenSSL                          |
| [Certificates](../examples/certificates/README.md)               | PEM/DER metadata, fingerprints, explicit TLS trust and actual CRL denial | Disposable loopback TLS and OpenSSL                            |
| [HTTP hello service](../examples/hello-http/README.md)           | Typed route, response validation, OpenAPI and SIGTERM shutdown           | Local loopback sockets                                         |
| [Observability](../examples/observability/README.md)             | Safe structured logs and actual process CPU/RSS/loop quantities          | None                                                           |
| [OIDC tenants](../examples/oidc-tenants/README.md)               | Signed assertions, issuer/audience, scopes and tenant provenance         | Disposable loopback issuer                                     |
| [Distributed tracing](../examples/distributed-tracing/README.md) | Two HTTP hops, W3C trace correlation and safe logs                       | Loopback collector receiver; actual collector suite separately |
| [Tenant metering](../examples/metering/README.md)                | Independent technical events and durable JSONL output                    | Private temporary files and loopback issuer                    |
| [PostgreSQL](../examples/postgres/README.md)                     | Named binds, SQL transaction outcomes and safe numeric values            | Verified-TLS disposable PostgreSQL                             |
| [MySQL](../examples/mysql/README.md)                             | Its own native driver, precision and prepared statements                 | Verified-TLS disposable MySQL                                  |
| [MariaDB](../examples/mariadb/README.md)                         | Independent MariaDB results and awaited ownership cleanup                | Verified-TLS disposable MariaDB                                |
| [Oracle](../examples/oracle/README.md)                           | Exact NUMBER DTO conversion and Thin configuration                       | Mock contracts required; real Oracle optional and unverified   |
| [Redis](../examples/redis/README.md)                             | Expiration, NX outcomes and scoped native keys                           | Verified-TLS disposable Redis                                  |
| [etcd](../examples/etcd/README.md)                               | Exact revisions, CAS, watches and leases through `etcd3`                 | Authenticated disposable etcd 3.7                              |
| [MongoDB](../examples/mongodb/README.md)                         | Native BSON DTOs, aggregation and session transactions                   | Authenticated disposable replica set                           |
| [JSON cache](../examples/cache/README.md)                        | Checked values, tenant namespaces and expiration                         | Redis fixture                                                  |
| [Health](../examples/health/README.md)                           | Liveness, dependency readiness, HTTP status and drain                    | Redis fixture                                                  |
| [Messaging](../examples/messaging/README.md)                     | Core NATS semantics, error strategy and correlation                      | Verified-TLS disposable NATS                                   |

The [DNS project](../examples/dns/README.md) additionally exercises all approved
native DNS record families against its owned loopback authority, resolver
isolation, OS lookup differences and actual SDK metric/log privacy.

The [LDAP project](../examples/ldap/README.md) verifies enterprise directory lookup,
isolated password binds, nested groups and private SDK metrics against the owned
OpenLDAP fixture. Verified LDAPS and STARTTLS remain mandatory in test.

The [outgoing OAuth guide](../examples/postgres/oauth-client.md) composes the native
OIDC client, external cryptographic keys and shared PostgreSQL state. Run its
owned HTTPS fixture wrapper around the complete PostgreSQL integration suite.

The [XLSX project](../examples/xlsx/README.md) writes and reads typed, styled
worksheets through explicit native streaming workers and tests actual SDK
memory, size and latency metadata without exposing workbook contents.

The [PDF project](../examples/pdf/README.md) composes searchable pages, adds rotated
text and verifies native resource observations while signature policy remains
enforced independently by every rewriting operation.

The [SFTP project](../examples/sftp/README.md) streams files through host-pinned
OpenSSH, publishes with a proven POSIX rename capability and executes only trusted
command IDs. Its live suite also checks private SDK observations.

The [AMQP project](../examples/amqp/README.md) uses verified RabbitMQ connections,
native publisher confirms, mandatory returns and single-use manual acknowledgments.
Its owned broker fixture and compiled consumer also verify private SDK observations;
wire tenant metadata never establishes tenant authority.

The [XML project](../examples/xml/README.md) roundtrips ordered namespace-aware
documents and validates against registered offline XSD assets with a vetted
native engine. Its disposable fixture isolates networking and verifies actual
standard/detailed SDK exports without document contents or schema locations.

## Verify the distributed package boundary

Workspace builds are useful during development. An independent check also packs
every implementation package, installs those archives in an external private
directory, recompiles all example source and tests, and executes every example's
unit/CLI suite against the installed artifacts:

```sh
pnpm test:packed:examples
```

Selected suites use their exact compiled filename pattern, including integration
files without a `.test` suffix. The verifier resolves the independent dependency
graph without executing install scripts, then applies only required reviewed
compatibility diffs copied byte-for-byte from their package archives. An empty
selected suite, absent diff or mismatch with reviewed source fails verification.

During development, select one example for the same isolated package installation,
strict source/test compilation and executable public-artifact check:

```sh
pnpm test:packed:examples --example utilities
```

The default command and automatic CI retain every example suite.

This check keeps TypeScript strict, validates real public exports and uses the
unmodified registry NATS dependency. It does not publish packages, use source
aliases or silently apply the workspace's dependency patch to consumers. Native
driver build hooks are disabled for installation; the examples use the supported
JavaScript/Thin paths. Temporary artifacts are removed after the run.

A live packed example uses its fixture's private environment loader. For example:

```sh
python3 packages/messaging/test/fixtures/run.py /private/runtime/nats-fixture/environment.json pnpm test:packed:examples --integration messaging
```

Other supported live selections are `postgres`, `mysql`, `mariadb`, `redis`,
`etcd`, `mongodb`, `cache` and `health`; use each project's documented disposable
fixture environment. Missing infrastructure fails explicitly. Oracle live
compatibility remains a separate optional check and is never inferred from mock
or DTO tests.

## Handle errors and measurements

Preserve a `KitError` internally while returning only its safe JSON envelope to
clients. A timed-out write may have been applied; inspect its outcome and
reconcile business state before retrying. A raw tenant field, forwarded header,
trace or broker namespace is not proof of authenticated tenant authority.

Meter events contain technical facts and completeness gaps. Application payload
bytes differ from network traffic, wall durations can overlap, and process
CPU/RSS cannot be assigned exactly to concurrent requests. Tracing can be off
while verified tenant metering remains active. Refer to each package's measured
coverage before interpreting missing quantities.

The [native socket project](../examples/socket/README.md) exchanges real TCP, verified TLS, UDP and Unix bytes with complete application-owned cleanup.

The [JSON mapping project](../examples/json/README.md) validates offline Draft
2020-12 schemas and deployment-approved transformations through bounded native
workers, with explicit missing/null behavior and private SDK exports.
