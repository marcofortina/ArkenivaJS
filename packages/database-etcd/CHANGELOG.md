# Changelog

## 0.1.0

- Add an optional native etcd3 provider with verified mTLS, scoped raw bytes and exact bigint metadata.
- Add atomic CAS, bounded resumable watch iteration with explicit gaps and explicitly renewed owned leases.
- Isolate cancellation, bound admission/deadlines and preserve unknown submitted write outcomes.
- Add private disposable TLS/auth fixtures and real fault, lifecycle and precision tests.
