# Changelog

## 0.1.0

- Add optional native MongoDB document access with strict captured TLS/SCRAM configuration and bounded BSON-preserving operations.
- Expose exact opaque inserted IDs, actual modified/deleted counts and unchanged explicitly bounded aggregation pipelines.
- Own Core session transactions without callback replay, retain uncertain write/commit effects and verify cursor/session cleanup.
- Integrate application-owned telemetry and independent metering without logging document values or fabricating driver measurements.
