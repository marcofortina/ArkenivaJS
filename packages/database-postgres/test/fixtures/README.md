# Disposable PostgreSQL TLS tests

These Linux test fixtures require Docker Compose, Python 3, OpenSSL and
noninteractive `sudo chown` for the pinned image's existing uid/gid 999. Use an
isolated VM when services must stay off the development host. No package or
container engine is installed by these scripts.

Run from the workspace root, in the environment that will host the containers.
Choose a **new** absolute private directory outside every Git checkout:

```sh
export PG_FIXTURE_DIRECTORY="$HOME/arkeniva-postgres-test"
python3 packages/database-postgres/test/fixtures/prepare.py "$PG_FIXTURE_DIRECTORY"
docker compose -f packages/database-postgres/test/fixtures/compose.yaml up -d --wait --wait-timeout 90
pnpm install --frozen-lockfile
pnpm build
python3 packages/database-postgres/test/fixtures/run.py "$PG_FIXTURE_DIRECTORY/environment.json" pnpm coverage:postgres
python3 packages/database-postgres/test/fixtures/run.py "$PG_FIXTURE_DIRECTORY/environment.json" pnpm --filter @arkenivajs/example-postgres test:integration
docker compose -f packages/database-postgres/test/fixtures/compose.yaml down
```

The generator refuses an existing directory or a directory inside a Git checkout.
It creates random passwords, a three-day private CA, a localhost/IP server identity,
a deliberately wrong server identity signed by the same CA, and private files
(0600) in a private directory (0700). Do not commit, print or upload those files.
The runner reads its environment mapping without echoing URLs or passwords.
`--github-env "$GITHUB_ENV"` appends variables to GitHub's protected job environment
and masks the random application password for CI; it is unnecessary locally.

The exact PostgreSQL 18.6 image digest is pinned in `compose.yaml`. Both containers
run unprivileged with dropped capabilities, no privilege escalation, bounded CPU,
memory and process counts. The administrative bootstrap password stays in a
mounted file. Tests use a separate role without superuser, database creation or
role creation privileges. TCP connections require TLS and SCRAM authentication.

Ports default to loopback **15432** and **15433**. When connecting through a VM's
private NAT, configure its forwards and, inside the VM only, override
`PG_FIXTURE_BIND_ADDRESS` as appropriate. Keep the host's forwarded ports on
loopback. A client outside the VM needs a private copy of `ca.crt` and URLs whose
`sslrootcert` points at that client's copy; never disable verification to cross
the VM boundary. The tests verify failures from an untrusted CA, a wrong SAN and
a wrong password separately.

Missing endpoint variables fail the live suite. The explicit disposable marker is
mandatory: tests create owned schemas and terminate their own backend during a
deferred commit. They never auto-retry a transaction. Unit and contract tests run
without a server. Combined unit/contract/live coverage enforces 95% lines and
branches on the adapter's production `dist` modules, without coverage exclusions.

`down` removes only this Compose project's containers and network. Private bind
directories deliberately remain for inspection; remove them separately after
confirming their exact location and that the fixture is stopped. Never reuse them
for production or for a fresh certificate-generation run.
