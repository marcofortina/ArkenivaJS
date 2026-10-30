# Changelog

- Register the bounded GraphQL subscription connection, queue and event instruments with fixed result, queue and transport dimensions.

- Add fixed GraphQL dimensions and explicit operation, duration, complexity, item and rejection units.

- Add explicit inbound trace-scope isolation and fixed socket event labels with native payload and duration units.

## 0.1.0

- Add fixed CSV operation/outcome dimensions and explicit row, byte, duration, error and process RSS units; reject custom CSV label catalogs.

- Add closed CIE operation/outcome dimensions and seconds-based authentication duration, federation check and failure units; reject custom CIE identity/error label catalogs.

- Admit only fixed SPID operation/outcome dimensions and the required handshake/trust-failure counter units; reject private federation labels and arbitrary outcome values.

- Add fixed routing metric categories and narrowly scoped private routing-span identities while rejecting those identities from every metric path.
- Export messaging publication, subscription, health and processing durations in seconds with explicit buckets.

- Export cache and health duration histograms with second units and the shared explicit duration buckets.

- Permit bounded SQL operation labels and root-configured pool names, with explicit
  connection units for active/idle gauges.

- Add isolated OTel SDK providers, bounded metrics/spans, W3C correlation and explicit exporter lifecycle.
