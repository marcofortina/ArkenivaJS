# Disposable NATS TLS and account fixture

The pinned NATS 2.15.1 Alpine image runs as UID 1000 with a read-only filesystem,
all capabilities dropped, no new privileges and bounded CPU, memory and process
counts. JetStream is disabled. The broker requires TLS-first handshakes, an
authenticated client certificate and a separate scoped username/password. Two
accounts have disjoint randomly named subject namespaces. An independently
healthy second server presents a certificate with the wrong SAN.

Prepare secrets outside every Git checkout and keep the directory private:

```sh
python3 packages/messaging/test/fixtures/prepare.py /private/runtime/nats-fixture
python3 packages/messaging/test/fixtures/run.py /private/runtime/nats-fixture/environment.json docker compose -f packages/messaging/test/fixtures/compose.yaml config --quiet
python3 packages/messaging/test/fixtures/run.py /private/runtime/nats-fixture/environment.json docker compose -f packages/messaging/test/fixtures/compose.yaml run --rm --no-deps nats -t --config /fixture/nats.conf
python3 packages/messaging/test/fixtures/run.py /private/runtime/nats-fixture/environment.json docker compose -f packages/messaging/test/fixtures/compose.yaml up -d --wait --wait-timeout 60
```

The parent directory must already exist. OpenSSL, Python 3 and a usable Docker
Compose environment are required. Run these services in a dedicated VM or an
ephemeral CI runner. The preparation script changes ownership only for the
exact server-mounted files when the invoking UID differs from 1000. Client
keys, the CA signing key and the private environment remain with the caller.
Nothing modifies the system certificate store or enables a host daemon.

Published fixture ports bind to loopback by default. `NATS_FIXTURE_PORT` and
`NATS_WRONG_SAN_PORT` change the container host ports; their defaults are 14223
and 14224. `NATS_FIXTURE_BIND_ADDRESS` exists for isolated VM forwarding. A VM
deployment should still bind the laptop-side forwarding sockets to loopback.
No cluster or monitoring endpoint is published. The container-local monitoring
health check confirms listener startup; it does not replace authenticated
native-client readiness tests.

Keep `environment.json`, passwords, signing keys and server/client private keys
outside the product repository. Never print its URLs. Host-side native clients
need only the fixture client key/certificate and public CA, with private local
permissions; the server and CA signing keys stay in the VM. TLS certificate
files are short-lived and must be regenerated through a new private fixture
directory when expired.

Stop only this explicitly owned disposable fixture:

```sh
python3 packages/messaging/test/fixtures/run.py /private/runtime/nats-fixture/environment.json docker compose -f packages/messaging/test/fixtures/compose.yaml down
```
