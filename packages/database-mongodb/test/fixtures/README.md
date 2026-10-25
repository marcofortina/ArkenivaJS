# Disposable MongoDB TLS/SCRAM replica set

Run only in a dedicated QEMU VM or ephemeral CI runner with Docker/Compose,
Python 3, OpenSSL and noninteractive `sudo chown`. Do not install database
services or Docker on a developer laptop for this fixture. The server image is
`mongo:9.0.4@sha256:dc28ed5a9d0fc616903c3f463bb1e53b92b49f441721b91926e87d90bf957ce8`.
The actual image runs mongod as UID/GID 999 with a read-only root, dropped
capabilities, bounded memory/CPU/PIDs, private temporary home and owned data.

Choose a new runtime directory outside every Git checkout; its parent must
already exist. Preparation creates private three-day certificates, random
SCRAM credentials and an internal replica-set key, with a mode-0600 environment
file. CA signing and bootstrap administrator secrets are never server mounts.
Only the read-only probe identity is mounted for health checks. The application
has read/write authority on its random disposable database.

```sh
python3 packages/database-mongodb/test/fixtures/prepare.py /private/runtime/mongodb-fixture
python3 packages/database-mongodb/test/fixtures/run.py /private/runtime/mongodb-fixture/environment.json docker compose -f packages/database-mongodb/test/fixtures/compose.yaml up -d
python3 packages/database-mongodb/test/fixtures/bootstrap.py /private/runtime/mongodb-fixture
python3 packages/database-mongodb/test/fixtures/run.py /private/runtime/mongodb-fixture/environment.json docker compose -f packages/database-mongodb/test/fixtures/compose.yaml up -d --wait --wait-timeout 90
pnpm build
python3 packages/database-mongodb/test/fixtures/run.py /private/runtime/mongodb-fixture/environment.json pnpm --filter @arkenivajs/database-mongodb coverage
python3 packages/database-mongodb/test/fixtures/run.py /private/runtime/mongodb-fixture/environment.json docker compose -f packages/database-mongodb/test/fixtures/compose.yaml down
```

Bootstrap runs once on fresh data. Do not wait for authenticated health before
bootstrap has created users. It uses the localhost exception from Docker exec
over each container's loopback, initiates its one-member `arkeniva` replica set,
waits for primary and creates the first administrator before authenticating
and creating scoped application/probe users. Secrets travel over stdin to
`mongosh --file /dev/stdin`, not command arguments. The regular and wrong-SAN
servers are separate healthy replica sets; the latter is a certificate identity
negative test rather than a broken service.

Default host bindings are loopback ports 27018/27019. For QEMU user networking,
set `MONGODB_FIXTURE_BIND_ADDRESS=0.0.0.0` only inside the guest and forward each
port to host loopback only. Host tests need just the public CA and private
application URI/environment, with the CA's absolute path adapted to the host.
Never copy the CA signing key or server keys to the host. Keep all runtime
credentials, data and logs outside Git. Direct connection is explicit because
the member's internal localhost port differs from the QEMU forwarded port;
this fixture does not test multi-member discovery/failover.

Live suites require `ARKENIVA_MONGODB_DISPOSABLE=1`, `ARKENIVA_MONGODB_URL` and
`ARKENIVA_MONGODB_WRONG_SAN_URL`. Tests use random owned collections and remove
them before closing their clients. TCP fault relays bind ephemeral loopback
ports and forward to the dedicated endpoint on 127.0.0.1:27018, dropping
encrypted replies without terminating TLS or implementing MongoDB framing.
Run each local Node qualification sequentially against the shared fixture;
each CI matrix job gets its own servers.

Stop the exact Compose project before removing its runtime directory. Verify
the directory's ownership and exact path first; guest container data may need
administrative cleanup inside that VM.
