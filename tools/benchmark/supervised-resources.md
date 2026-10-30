<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Supervised Linux benchmark resource observations

`runSupervisedWorker(workerFile, input, options)` is an internal benchmark helper.
It is not connected to any existing comparison controller or framework runtime.
The caller supplies a trusted absolute worker file or file URL. The worker receives
one input through native Node advanced IPC, sends one result message, and must exit
successfully. Input/result values may include Buffer and bigint. Opaque V8 payloads
travel only through pipes; fixture values never enter argv, environment or errors.
Worker stdout/stderr are discarded, and supervisor errors use fixed diagnostics.

The helper checks Linux, readable `/proc` data, Python `wait4`, pidfds and subreaper
support before spawning the worker. No package installation, privileged operation,
cgroup configuration or process-name cleanup is performed. Unsupported facilities
fail explicitly. Limits bound timeout, cleanup grace, sampling interval, serialized
messages, protocol output, 64 active process identities, 4,096 total observed
identities and sampling rounds. Departed pidfds are closed so sequential native
operations do not consume active slots indefinitely. Oversized input
or output is rejected rather than truncated. Cancellation and timeout wait for
physical retirement before returning an error with completed resource observations.

The Python supervisor owns a new Node session containing a Node bridge, the actual
worker and its native descendants. Node-to-Node IPC remains unchanged; Python never
acts as a Node IPC peer. The supervisor captures same-user parent/start-time lineage,
discovers only supervisor/owned task-child lists, without scanning unrelated
processes. It pins descendants with pidfds, signals only its owned group/descendants,
adopts orphans and reaps every child. Tests include a legitimate detached descendant
and a separate sentinel that must remain alive. This covers the tested controlled
process model, not arbitrary hostile daemonization, UID/namespace changes or every
possible escape from process ownership. Startup and root inspection remain inside
cleanup protection. Bounded stdin transfer uses selectable nonblocking writes, so
a bridge that never reads its input cannot disable timeout or abort handling.

`resource.scope` is `whole-supervised-lifecycle`: CPU includes Node bridge/worker
startup, verification, warmup, measurement, export, cleanup and exit. Summed `wait4`
user/system seconds include descendants waited by their ancestor; no sampled child
CPU is added again. Python observer CPU and external servers are excluded. These
values must remain separate from existing measured-window CPU fields.

`sampledSummedRssPeakBytes` sums owned processes' `smaps_rollup` RSS observations.
It is sampled and non-atomic, can miss brief peaks, and counts shared resident pages
in each process. It is neither PSS nor unique physical RAM. In contrast,
`rssReadQuality` separately counts inaccessible and vanished observations; access
denials make `allObservedReadsAccessible:false`. Partial-access observations cannot
establish complete RSS coverage or release acceptance. A privileged observer may
still read a nondumpable synthetic child; the negative control inspects that actual
capability instead of claiming that access was denied.
`largestSingleProcessRssBytes` retains the Linux `wait4` maximum single-process RSS;
it is not a process-tree sum. Sampling overhead can perturb workloads, and actual
maximum sampling gaps are reported. Every comparison profile must use the same
method before drawing relative conclusions. This helper alone establishes no
native-policy equivalence, resource parity, release budget or production readiness.

References: [Python wait4](https://docs.python.org/3/library/os.html#os.wait4),
[Linux resource accounting](https://man7.org/linux/man-pages/man2/getrusage.2.html),
[Linux subreapers](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html),
[proc filesystem](https://www.kernel.org/doc/html/latest/filesystems/proc.html) and
[Node child-process IPC](https://nodejs.org/api/child_process.html#optionsstdio).
