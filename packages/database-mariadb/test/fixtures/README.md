# Disposable MariaDB integration servers

This fixture uses the pinned official **MariaDB 12.3.3 LTS** image and its existing
unprivileged mysql uid/gid 999. It is independent of the MySQL server/driver fixture.
Both containers have resource limits and TLS; the application account has only
database-scoped privileges on `arkeniva_test`, with no global administration grant.
The negative endpoint presents a trusted certificate with the wrong identity.

On a disposable Linux machine with Docker Compose, Python, OpenSSL and passwordless
`sudo chown`, prepare a **new directory outside every Git checkout**:

```sh
python3 packages/database-mariadb/test/fixtures/prepare.py /tmp/arkeniva-mariadb-private
python3 packages/database-mariadb/test/fixtures/run.py /tmp/arkeniva-mariadb-private/environment.json docker compose -f packages/database-mariadb/test/fixtures/compose.yaml up -d --wait --wait-timeout 180
python3 packages/database-mariadb/test/fixtures/run.py /tmp/arkeniva-mariadb-private/environment.json node --test packages/database-mariadb/dist-test/integration/mariadb.integration.test.js
```

Build the workspace before running compiled tests. The generator refuses reused,
checkout-contained or newline-containing paths. Keys and environment JSON remain
private; a separate CA copy for the invoking client user and for server uid 999
keeps both readable by their actual owners at mode 0600. The runner checks private
file permissions and never prints credentials.

The official `healthcheck.sh --connect --innodb_initialized` probe checks final
networking and initialized InnoDB, excluding the entrypoint's temporary server.
Native startup queries additionally verify application authentication and TLS.
Tables use unique, bounded test identifiers and are cleaned up by their owner.
Tests deliberately exercise native connection termination and uncertain commits;
set the disposable marker only for a disposable database.

Host ports 13307 and 13309 bind to loopback by default. For QEMU user networking,
set `MARIADB_FIXTURE_BIND_ADDRESS=0.0.0.0` **inside the guest** and forward those
guest ports to loopback-only host ports. Host-side URLs need their own readable CA
path, rather than a guest-only file location. Do not mount host data into the VM.

Stop this project with the same private runner/Compose file and `down`. Bind data
and private credentials remain for inspection and separately controlled cleanup.
