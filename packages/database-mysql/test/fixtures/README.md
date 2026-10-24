# Disposable MySQL integration servers

The pinned official MySQL 9.7.4 LTS image runs as its existing unprivileged user,
with resource limits and verified TLS. The application account can access only
`arkeniva_test`; it has no global administration privileges. Tests require an
explicit disposable marker and create uniquely named tables in that database.

On a disposable Linux test machine with Docker Compose, Python, OpenSSL and
passwordless `sudo chown`, prepare a **new directory outside every Git checkout**:

```sh
python3 packages/database-mysql/test/fixtures/prepare.py /tmp/arkeniva-mysql-private
python3 packages/database-mysql/test/fixtures/run.py /tmp/arkeniva-mysql-private/environment.json docker compose -f packages/database-mysql/test/fixtures/compose.yaml up -d --wait
python3 packages/database-mysql/test/fixtures/run.py /tmp/arkeniva-mysql-private/environment.json pnpm coverage:mysql
```

Keep the directory, keys and environment JSON private. The invoking user owns the
client CA copy; mysql uid 999 owns a separate server CA copy. Both files have mode
0600, so a non-root test process can read its trust anchor without exposing keys.
Preparation rejects an
existing directory and never prints credentials except a GitHub Actions masking
directive when explicitly asked to append to `GITHUB_ENV`. The runner checks file
permissions before reading variables. `mysqladmin ping` requires the final TCP
listener, excluding the entrypoint's socket-only temporary initialization server;
the adapter's startup query additionally authenticates the restricted account.

The second endpoint presents a certificate from the same trusted CA with an
incorrect DNS identity. It must fail before authentication. Host ports bind only
to loopback by default. For QEMU user networking, override
`MYSQL_FIXTURE_BIND_ADDRESS=0.0.0.0` **inside the disposable guest** and forward
guest ports 13306 and 13308 to loopback-only host ports. Never mount host data or
private fixtures into the product checkout.

Use the same private runner and Compose file with `down` to stop these services.
Private bind directories deliberately remain for inspection and separate cleanup.

CI runs combined unit/contract/live tests with a 95% line/branch floor, and the
built orders consumer, on each supported Node version. The same commands work
with the prepared environment; no test credentials are embedded in the workflow.
