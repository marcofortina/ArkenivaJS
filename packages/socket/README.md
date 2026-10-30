# Native socket servers

`@arkenivajs/socket` is an optional server adapter over `node:net`, `node:tls`
and `node:dgram`. It implements no TLS, TCP/UDP protocol stack, application
framing, client dialer, DTLS, QUIC, broadcast, multicast or proxy protocol.
Importing the package and constructing its plugin opens no listener.

```typescript
import { createApplication } from '@arkenivajs/core';
import { socketPlugin, SOCKET_CAPABILITY } from '@arkenivajs/socket';
import type { SocketService } from '@arkenivajs/socket';

const app = await createApplication({
  service: { name: 'raw-service', version: '1.0.0', environment: 'production' },
  plugins: [
    socketPlugin({
      listeners: [
        {
          kind: 'tcp',
          options: { name: 'echo', port: 9001 },
          handler: async (peer) => {
            for await (const bytes of peer.chunks()) await peer.send(bytes);
            await peer.end();
          },
        },
      ],
    }),
  ],
});
await app.start();
const sockets = app.resolve<SocketService>(SOCKET_CAPABILITY);
const later = sockets.createUdpServer(
  { name: 'datagrams', family: 'udp4', port: 9002 },
  async (datagram, server) => {
    await server.reply(datagram, datagram.bytes);
  },
);
await later.start();
await app.stop();
```

The [complete executable example](../../examples/socket/README.md) includes real
verified TLS, TCP, UDP and Unix clients with disposable fixtures and cleanup.

Static definitions validate before activation and bind before READY. A failed
activation closes earlier listeners. Dynamic handles remain CREATED until
`start()`; the application owns and closes them even when their caller forgets.
Names are unique for that service lifetime; at most 128 handles are admitted.
`list()` exposes only safe names, kinds, state and bindings. `start()` is
idempotent while LISTENING; FAILED/CLOSED handles cannot be restarted. Create a
new named handle to bind again. `stop()` is permanent and idempotent.

| Policy              | Default and finite bounds                                              |
| ------------------- | ---------------------------------------------------------------------- |
| Host                | `127.0.0.1`, or `::1` for udp6; strict literal IP only                 |
| Port                | Required `1..65535`; `0` permitted only by the owning test application |
| IPv6                | Explicit `ipv6Only`; defaults true for predictable family behavior     |
| Connections         | 1024; `1..100000`, pending TLS handshakes included                     |
| Idle timeout        | 60000 ms; `1..86400000`                                                |
| Pending writes      | 1 MiB per peer; `1..16 MiB`, at most 64 pending writes                 |
| TLS handshake       | 10000 ms; `1..120000`                                                  |
| Shutdown            | 30000 ms; `1..120000`, also canceled by the application lifetime       |
| Datagram bytes      | 1200; `1..65507`                                                       |
| UDP handlers        | 256; `1..4096`, with a 16 MiB active-input ceiling                     |
| UDP queue           | 1024; `1..16384`, with an 8 MiB aggregate payload ceiling              |
| UDP reply           | 1200 bytes; `1..65507`, cumulative per datagram                        |
| Reply amplification | 1; explicit integer `1..16`, multiplied by original receive bytes      |
| UDP sends           | At most the handler limit and 16 MiB outstanding owned payload         |

Null, unknown fields, getters, malformed profiles, unsupported combinations and
nonpositive timeouts fail before native I/O. Operation signals are native
AbortSignal values, never trusted structural lookalikes; operation deadlines can
only shorten deployment limits. Errors expose fixed English messages without
addresses, paths, payloads, certificate bytes or secret references.

TCP/TLS/Unix chunks are arbitrary byte sequences. Only one consumer can call
`chunks()`; iterator return destroys the connection. `send()` copies admitted
bytes and waits for the native write callback plus `drain` when needed. This
means writable acceptance, not remote receipt. Abort/deadline destroys that
connection; already accepted bytes may have been sent, so no rollback or retry
is promised. `end()` half-closes the local writable path; protocols that do not
consume peer EOF must explicitly `close()` when finished. Handler rejection
closes only its connection, increments safe counters and emits one fixed error
observation. Graceful stop stops acceptance, drains existing streams, then
destroys survivors at the deadline. Uncooperative application promises can finish
later; they do not retain a live listener after forced shutdown.

TLS settings are the existing `ServerTlsFiles` from core, with minimum TLS 1.2
and optional required client certificates under an explicit CA. Both HTTPS and
raw TLS use the same lazy native file/context loader: bounded regular files,
native certificate dates and OpenSSL key matching, explicit passphrase environment
reference, and temporary buffer clearing. No private material belongs in Git.
The application handler runs only after secureConnection; renegotiation is
disabled. Pending unauthenticated handshakes are destroyed when drain starts.

UDP defaults to reply-only operation. A received datagram is an owned, immutable
envelope; its byte array is a caller-owned snapshot. Mutating bytes or cloning an
envelope cannot change the original destination or amplification budget. Reply
authority expires when its handler settles; it never conveys authentication.
Multiple replies share the original budget, reserved before native send. Explicit
`sendTo` requires `allowOutboundDestinations:true` plus `destinationAllowlist` of
exact literal `IPv4:port` or `[IPv6]:port` strings of the listener's family. No
DNS or user-selected fallback destination is used. Empty datagrams remain empty.
Outbound stream/datagram payloads are bounded and copied through native
typed-array slots, including nonzero-offset views. Instance `length`,
`byteLength`, `buffer`, `byteOffset`, iterator and conversion metadata are not
evaluated. Proxy views and shared backing memory are rejected before native
submission; reply reservations use the actual captured byte count.
Overload drops are counted; ordering, packet loss and delivery are native UDP
properties and are never converted into reliability promises.

Unix paths require an absolute normalized pathname, an owned canonical directory
with mode 0700, and a conservative 103-byte native bind-path ceiling. Symlinks,
existing files/sockets, stale paths and foreign-owned directories are rejected;
there is no stale-path deletion. A private mode-0700 sibling directory owns the
short native bind pathname. A hard link publishes the socket atomically without
overwriting a concurrent endpoint; the private bind pathname is removed. The
private directory remains reserved until close. Node's automatic unlink therefore
cannot target a replacement of the public pathname. Cleanup checks the published
socket's device/inode/owner and removes only the matching owned socket, then its
empty private directory. No process-global umask is changed. Same-user writes to
the trusted directory must remain coordinated by the application. Windows Unix
sockets are unsupported; other POSIX filesystem/link capabilities need actual
platform verification.

Optional existing logging, telemetry and metering owners are resolved through
the scoped support SPI. Their `withoutScope` controls are required at startup,
so inbound handlers cannot inherit the registering request's framework log fields,
trace or tenant accounting session. Native resources also execute in the owner's
bootstrap async scope, protecting dynamic listeners from later registering task
contexts. Raw IP, payload, TLS certificate and correlation IDs grant no tenant
authority. Unattributed traffic is observed through aggregate statistics/OTel;
it is never recorded as a fabricated tenant meter event. Authenticate an explicit
application protocol before creating a verified tenant meter session.

Fixed metric labels are only `socket.kind`, `socket.event`, `socket.outcome`.
`socket.event.count` counts observed events; `socket.payload.bytes` is application
payload in `By`, excluding packet/TLS overhead. `socket.pending.bytes` and
`socket.active.connections` aggregate owned resources per transport kind.
Handler/observed handshake histograms use milliseconds. Failed diagnostics
increment `socket.observation.dropped` when possible and never replay work.
These quantities do not measure packet delivery, NIC traffic, exact per-request
CPU/RAM, infrastructure charges or costs.

Stable failure categories are `EK_SOCKET_CONFIG`, `EK_SOCKET_BIND`,
`EK_SOCKET_STATE`, `EK_SOCKET_CLOSED`, `EK_SOCKET_CAPACITY`, `EK_SOCKET_IO`,
`EK_SOCKET_TLS_HANDSHAKE`, `EK_SOCKET_DATAGRAM`, `EK_TIMEOUT`, `EK_ABORTED` and
`EK_UNSUPPORTED_CAPABILITY`. Externally reachable listeners need explicit bind
addresses and deployment firewall/NetworkPolicy rules; raw sockets inherit no
HTTP authentication, cookies or forwarded identity headers.

Stream read counters count bytes yielded to the application consumer; they do
not infer unread kernel-buffer contents. UDP receive counters include observed
payloads rejected by application admission, with separate drop counts.
