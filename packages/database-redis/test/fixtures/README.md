# Disposable Redis integration fixture

Run this fixture in a dedicated Linux VM or ephemeral CI runner with Docker
Compose, Python 3, OpenSSL and passwordless `sudo chown`. It does not install
system services. Keep private runtime files **outside every Git checkout**.
The generator requires a new directory, creates private credentials and a
three-day CA, and assigns only server-readable files/data directories to uid/gid 999. It retains a separate caller-readable CA. Never print `environment.json`.

The pinned Redis 8.10.2 image serves verified TLS on port 16379 and a separately
healthy, deliberately wrong-SAN certificate on 16380. Plaintext is disabled.
The default user is disabled. Application keys/channels have a random ACL prefix;
the probe can only PING. A separate control account can inspect the version and
target clients or pause this **dedicated** test server. AOF is enabled, memory,
clients and container resources are bounded, and the root filesystem is read-only.
The CA private key is never mounted into a container.

From the product checkout on the VM/runner:

```sh
python3 packages/database-redis/test/fixtures/prepare.py /private/runtime/redis-fixture
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json docker compose -f packages/database-redis/test/fixtures/compose.yaml up -d --wait --wait-timeout 90
pnpm build
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json pnpm coverage:redis
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json docker compose -f packages/database-redis/test/fixtures/compose.yaml down
```

Create the private parent directory first with mode 0700. Do not run these
commands against customer or production services. Integration tests require
`ARKENIVA_REDIS_DISPOSABLE=1`, `ARKENIVA_REDIS_URL`,
`ARKENIVA_REDIS_WRONG_SAN_URL` and `ARKENIVA_REDIS_CONTROL_URL`, all emitted by the
generator. GitHub Actions can use `--github-env "$GITHUB_ENV"`; generated passwords
are masked before writing their environment entries.

Default published ports bind to 127.0.0.1. When the client runs outside a VM,
forward only those two ports on host loopback. `REDIS_FIXTURE_BIND_ADDRESS=0.0.0.0`
is an explicit guest-side override for VM forwarding, not a host exposure default.
Copy only the public CA to a private host path and rewrite `sslca` in privately
captured client URLs. Keep container/data directories on the guest. Redis's
recommended `vm.overcommit_memory=1`, if needed, belongs only to the disposable
VM/runner; no host kernel change is needed.

Fault tests pause the server briefly and kill only their identified client ID.
Run each Node matrix job against its own fixture or sequentially on the same VM.
Tests track and delete only their own random keys and destroy native duplicates
and control clients. The wrong-SAN endpoint must be healthy before TLS rejection
is meaningful. Container startup/health failures fail the gate. Inspect private
logs without copying credentials, generated certificates or raw runtime output
into Git. Use Compose `down` for owned containers; private data may be retained
outside the product for troubleshooting or removed after the run.
