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

PostgreSQL 18.6 is the default; `--server-major 17` selects PostgreSQL 17.11.
Both exact image digests are reviewed and pinned in `prepare.py`, with the
existing 18.6 fallback retained in `compose.yaml`. Both containers
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

To run the second reviewed server on the same disposable VM, choose a new
private directory and distinct ports. Use the private environment runner for
Compose so the selected image, data layout and port mapping stay consistent:

```sh
python3 packages/database-postgres/test/fixtures/prepare.py "$PG_FIXTURE_DIRECTORY" --server-major 17 --port 15434 --wrong-san-port 15435
python3 packages/database-postgres/test/fixtures/run.py "$PG_FIXTURE_DIRECTORY/environment.json" docker compose -p arkenivajs-postgres17-test -f packages/database-postgres/test/fixtures/compose.yaml up -d --wait --wait-timeout 90
python3 packages/database-postgres/test/fixtures/run.py "$PG_FIXTURE_DIRECTORY/environment.json" pnpm coverage:postgres
python3 packages/database-postgres/test/fixtures/run.py "$PG_FIXTURE_DIRECTORY/environment.json" docker compose -p arkenivajs-postgres17-test -f packages/database-postgres/test/fixtures/compose.yaml down
```

Do not reuse data or a fixture directory across server majors. Unsupported
majors, privileged/invalid/equal ports and destinations inside Git are rejected
before credentials are created. Check these input guards without starting a
service using `python3 packages/database-postgres/test/fixtures/test_prepare.py`.

Missing endpoint variables fail the live suite. The explicit disposable marker is
mandatory: tests create owned schemas and terminate their own backend during a
deferred commit. They never auto-retry a transaction. Unit and contract tests run
without a server. Combined unit/contract/live coverage enforces 95% lines and
branches on the adapter's production `dist` modules and its shared SQL deadline
implementation, without coverage exclusions.

`down` removes only this Compose project's containers and network. Private bind
directories deliberately remain for inspection; remove them separately after
confirming their exact location and that the fixture is stopped. Never reuse them
for production or for a fresh certificate-generation run.
