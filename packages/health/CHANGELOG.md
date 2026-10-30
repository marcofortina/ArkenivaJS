# Changelog

## 0.1.0

- Capture readiness callbacks and their original receivers without invoking mutable binding metadata, accessors or proxy traps.

- Add bounded concurrent dependency probes with explicit startup, retained pending ownership and cancellation-aware cleanup.
- Consume scoped native plugin health hooks without granting access to foreign private components.
- Integrate safe HTTP readiness with actual backend failure and recovery, independent process liveness and lifecycle checks after asynchronous work.
