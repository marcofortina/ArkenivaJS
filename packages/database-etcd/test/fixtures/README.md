# Disposable etcd mTLS fixture

Run these commands only inside a dedicated QEMU VM or ephemeral CI runner with
Docker/Compose, Python 3, OpenSSL and noninteractive `sudo chown`. Do not install
database services or Docker on a developer laptop for this fixture. The pinned
image is etcd 3.7.3 at
`sha256:0d27b9478551f431f82d1e0ddb6c87ad07ebae8b904c637f3a99213349523910`.
The containers run as UID/GID 65532 with a read-only root, dropped capabilities,
bounded memory/CPU/PIDs and private writable data directories.

Choose a **new directory outside every Git checkout**. Its parent must exist.
`prepare.py` creates private three-day certificates, random namespaces and a
mode-0600 environment file, without printing identities or URL material.
Caller-owned client keys remain separate from container-owned server and probe
copies. The CA signing key and root client identity are never mounted in servers.

```sh
python3 packages/database-etcd/test/fixtures/prepare.py /private/runtime/etcd-fixture
python3 packages/database-etcd/test/fixtures/run.py /private/runtime/etcd-fixture/environment.json docker compose -f packages/database-etcd/test/fixtures/compose.yaml up -d --wait --wait-timeout 90
python3 packages/database-etcd/test/fixtures/bootstrap.py /private/runtime/etcd-fixture
python3 packages/database-etcd/test/fixtures/run.py /private/runtime/etcd-fixture/environment.json docker compose -f packages/database-etcd/test/fixtures/compose.yaml ps
pnpm build
python3 packages/database-etcd/test/fixtures/run.py /private/runtime/etcd-fixture/environment.json pnpm coverage:etcd
python3 packages/database-etcd/test/fixtures/run.py /private/runtime/etcd-fixture/environment.json docker compose -f packages/database-etcd/test/fixtures/compose.yaml down
```

Bootstrap runs once on fresh data. Its short-lived client mounts only the root
client identity and public CA to enable certificate authentication and server
roles. The app identity can read/write only its random prefix; the probe identity
can read only the health key; the negative client identity has no registered user.
Both the regular and wrong-SAN servers remain independently healthy after auth
is enabled. The control/root URL is required only for actual compaction tests.

Default host bindings are loopback ports 12379/12380. For laptop access through
QEMU user networking, bind these ports to guest interfaces only via
`ETCD_FIXTURE_BIND_ADDRESS=0.0.0.0`, and use host-loopback-only QEMU forwarding.
Copy only the public CA and application/control/negative client material needed
by authorized tests to private host files; adapt their absolute paths in a
mode-0600 host environment file. Never copy the CA private key to the host or
commit fixture identities, data, operational logs or runtime environment files.

Live tests require `ARKENIVA_ETCD_DISPOSABLE=1`, `ARKENIVA_ETCD_URL`,
`ARKENIVA_ETCD_CONTROL_URL`, `ARKENIVA_ETCD_WRONG_SAN_URL` and
`ARKENIVA_ETCD_UNKNOWN_IDENTITY_URL`. They operate on random owned keys and
include destructive global compaction. Each CI matrix job needs its own server;
local runs sharing the VM must run sequentially. Test TCP relays are ephemeral
loopback proxies to the configured disposable endpoint and do not terminate TLS.

Keep the private runtime directory until Compose has stopped its exact project.
Remove that directory only after checking ownership and the exact path; it holds
container-owned data and may require administrative cleanup inside the VM.
