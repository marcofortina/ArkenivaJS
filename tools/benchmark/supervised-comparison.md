<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Optional process-tree observations in comparison reports

A trusted comparison definition may declare the own data property
`superviseProcessTree:true`. The flag is captured once and applies to all four
measured profiles. Only opt-in `--smoke` dynamically loads the Linux supervisor.
Existing definitions and every `--verify` invocation retain the original direct
fork and report shape. This step enables no existing adapter automatically.

For opt-in measurements, each row appends `processTreeResource` while `resource`
continues to describe the original measured-window worker observations. The separate
`processTreeResourceCoverage` states that user/system CPU seconds cover the entire
Node bridge/worker/native-descendant lifecycle: startup, verification, warmup,
measurement, export and physical cleanup. Python observer, parent/collector and
external servers remain excluded. RSS bytes distinguish sampled non-atomic sums
from the maximum single-process resident set. Shared pages may repeat and brief
peaks may be missed; these values are not PSS or exact per-operation memory.

The comparison refuses inaccessible RSS or descendant discovery, traversal-limit
truncation, invalid resource values and incomplete physical cleanup. Vanished
short-lived observations remain explicit quality metadata. Successful observations
do not establish native-policy equivalence, calibrated overhead or release budgets.

Supervised measurements currently reject `trustAnchorFile` before report directory,
collector or worker creation. They never silently discard a requested trust anchor.
The original path retains its existing CA behavior. Supervised Python/Node processes
receive only the explicit safe execution environment and opaque pipe/IPC fixture
data; coordinator database credentials, `NODE_OPTIONS` and unrelated variables are
not inherited. Application-owned provider callbacks remain in their owning process.

The dedicated synthetic integration exercises real native child CPU/memory/IPC,
four profiles, preserved default/verification behavior, private environment controls,
and an actual inaccessible-RSS refusal. It runs no real codec or external service;
its tiny loopback collector is limited to existing SDK correctness observations.
