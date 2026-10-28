# Changelog

## 0.1.0

- Add an optional named Pub/Sub capability with dedicated scoped native
  subscribers, bounded callback queues, explicit failure handling and owned cleanup.

- Add an owned readonly readiness hook for optional health collectors without relaxing public facade lifecycle guards.

- Add the optional native Redis provider with strict TLS/ACL configuration,
  scoped UTF-8 values, NX/millisecond TTL, exact safe counters and Pub/Sub counts.
- Bound commands and results, expose explicit native ownership and surface
  uncertain writes without automatic replay.
- Include disposable real-server fault tests and portable lifecycle contracts.
