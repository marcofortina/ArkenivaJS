# Changelog

## 0.1.0

- Export messaging publication, subscription, health and processing durations in seconds with explicit buckets.

- Export cache and health duration histograms with second units and the shared explicit duration buckets.

- Permit bounded SQL operation labels and root-configured pool names, with explicit
  connection units for active/idle gauges.

- Add isolated OTel SDK providers, bounded metrics/spans, W3C correlation and explicit exporter lifecycle.
