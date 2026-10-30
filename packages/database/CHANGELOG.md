# Changelog

## 0.1.0

- Capture request and lifetime cancellation before deadline bookkeeping; reject executable controls and verify actual query/transaction cleanup across native SQL drivers.
- Permit startup reads through already registered named drivers, preserving rejection before driver readiness and after close.
- Add portable SQL contracts and a bounded named binding compiler for PostgreSQL,
  MySQL, MariaDB and Oracle, with exact binding validation and seeded property tests.
- Add a resource-free per-application SQL coordinator, explicit native registration
  and transaction callback ownership guards through the adapter support entry.
