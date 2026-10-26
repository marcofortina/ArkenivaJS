# Native TCP, TLS, UDP and Unix sockets

This Linux/POSIX example uses actual `node:net`, `node:tls` and `node:dgram`
clients against application-owned listeners. It generates ephemeral EC certificate
files with the installed `openssl` command, trusts that certificate explicitly,
and deletes all files after closing the application. It needs no external server,
credentials, container engine or public network access.

```sh
pnpm --filter @arkenivajs/example-socket build
pnpm --filter @arkenivajs/example-socket start
pnpm --filter @arkenivajs/example-socket test
pnpm test:packed:examples --example socket
```

Expected CLI output:

```json
{ "tcpBytes": 4, "tlsBytes": 4, "unixBytes": 4, "udpBytes": 4, "privatePathRemoved": true }
```

The complete [source](src/main.ts) registers four named static listeners before
READY. Ports are assigned by the OS only because this disposable application
explicitly selects the test environment. Production must select approved positive
ports and externally managed certificate files. Native clients validate the TLS
peer; certificate verification is never disabled.

The payload contains arbitrary bytes. TCP/TLS/Unix reads can split or combine
writes and do not imply messages. UDP preserves individual datagrams in this
fixture; the OS send callback does not promise delivery in other environments.
Replies use only the received datagram's owned origin and cannot exceed the
default cumulative 1:1 amplification budget. No source address authenticates a
subject or tenant.

The Unix socket lives in an owned mode-0700 directory, uses mode 0600, and is
removed only while its inode is still owned. Native bind-path isolation prevents
Node's automatic close-time unlink from removing a replacement of the published
path. Windows Unix sockets are explicitly unsupported.

Run the package tests for IPv6 capability evidence, admission/backpressure,
abort/forced shutdown, failed startup rollback, mTLS and safe observer isolation.
Performance measurements and remote compatibility remain separate release gates.
