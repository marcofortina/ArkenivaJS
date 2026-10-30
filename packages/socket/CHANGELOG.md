# Changelog

## 0.1.0

- Bound and snapshot outbound TCP/UDP bytes through native typed-array slots; reject proxy/shared views and preserve cumulative UDP reply limits without evaluating instance metadata.
- Add explicit application-owned native TCP, TLS/TCP, UDP and Unix listeners.
- Bound connections, writes, datagrams, handlers, queues, cancellation and shutdown.
- Isolate inbound log/trace/accounting scopes and preserve Unix path ownership.
