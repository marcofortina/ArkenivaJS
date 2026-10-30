# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Linux benchmark supervisor; opaque payloads use ordinary pipes, never Node IPC."""
import ctypes
import json
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

os.umask(0o077)
assert sys.platform == "linux"
assert hasattr(os, "wait4") and hasattr(os, "pidfd_open")
assert hasattr(signal, "pidfd_send_signal")
assert Path("/proc/self/smaps_rollup").is_file()
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
libc.prctl.restype = ctypes.c_int
assert libc.prctl(36, 1, 0, 0, 0) == 0
if sys.argv[1:] == ["--probe"]:
    handle = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(handle, 0)
    finally:
        os.close(handle)
    print(json.dumps({"supported": True}))
    sys.exit(0)
assert not sys.argv[1:]
encoded = sys.stdin.buffer.read(2097153)
assert len(encoded) <= 2097152
configuration = json.loads(encoded)
for name, low, high in [
    ("timeoutMs", 1, 120000),
    ("cleanupGraceMs", 1, 1000),
    ("sampleIntervalMs", 5, 250),
    ("maxMessageBytes", 64, 1048576),
]:
    assert type(configuration[name]) is int and low <= configuration[name] <= high
assert all(
    Path(configuration[name]).is_absolute() for name in ["node", "bridge", "worker"]
)
interrupted = False


def interrupt(_signal, _frame):
    global interrupted
    interrupted = True


signal.signal(signal.SIGTERM, interrupt)
signal.signal(signal.SIGINT, interrupt)


def status(pid):
    path = Path("/proc") / str(pid)
    if path.stat().st_uid != os.getuid():
        # Nondumpable same-user processes can have root-owned proc directories.
        try:
            identity = next(
                line.split()[1:]
                for line in (path / "status").read_text().splitlines()
                if line.startswith("Uid:")
            )
        except PermissionError:
            return None
        if int(identity[0]) != os.getuid() or int(identity[1]) != os.getuid():
            return None
    parts = (path / "stat").read_text().rsplit(")", 1)[1].split()
    return {
        "pid": pid,
        "state": parts[0],
        "ppid": int(parts[1]),
        "pgid": int(parts[2]),
        "sid": int(parts[3]),
        "startTicks": int(parts[19]),
    }


def snapshot():
    global protocol_invalid
    result = {}
    pending = [os.getpid()]
    visited = set()
    while pending:
        pid = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        try:
            if pid != os.getpid():
                item = status(pid)
                if item is None:
                    continue
                result[pid] = item
            tasks = Path("/proc") / str(pid) / "task"
            for count, task in enumerate(tasks.iterdir()):
                if count >= 1024:
                    protocol_invalid = True
                    discovery_quality["traversalLimitExceeded"] = True
                    break
                try:
                    with (task / "children").open() as stream:
                        children = stream.read(65537)
                    if len(children) > 65536:
                        protocol_invalid = True
                        discovery_quality["traversalLimitExceeded"] = True
                        continue
                    for child in children.split():
                        value = int(child)
                        if value not in visited and value not in pending:
                            if len(pending) + len(visited) >= 4096:
                                protocol_invalid = True
                                discovery_quality["traversalLimitExceeded"] = True
                                break
                            pending.append(value)
                except (FileNotFoundError, ProcessLookupError):
                    discovery_quality["vanishedBeforeRead"] += 1
                except PermissionError:
                    discovery_quality["inaccessibleReads"] += 1
        except (FileNotFoundError, ProcessLookupError):
            discovery_quality["vanishedBeforeRead"] += 1
        except PermissionError:
            discovery_quality["inaccessibleReads"] += 1
    return result


began = time.monotonic()
process = None
group = None
owned = {}
history = set()
selector = selectors.DefaultSelector()
transferred = 0
pending_input = memoryview(encoded)
discovery_quality = {
    "inaccessibleReads": 0,
    "vanishedBeforeRead": 0,
    "traversalLimitExceeded": False,
}
protocol = bytearray()
error_bytes = 0
protocol_invalid = False
reaped_count = 0
user_cpu = system_cpu = largest_rss = 0
rss_peak = rss_single_peak = max_concurrent = sampling_rounds = 0
rss_inaccessible = rss_vanished = 0
last_sample = began
max_sampling_gap = 0
term_at = None
root_reaped = False
detached_observed = False


def discover(current):
    global detached_observed, protocol_invalid
    for pid, item in list(owned.items()):
        observed = current.get(pid)
        if observed is None or observed["startTicks"] != item["startTicks"]:
            os.close(item["pidfd"])
            del owned[pid]
    changed = True
    while changed:
        changed = False
        for pid, item in current.items():
            if pid in owned:
                continue
            parent = current.get(item["ppid"])
            inherited = (
                parent
                and parent["pid"] in owned
                and parent["startTicks"] == owned[parent["pid"]]["startTicks"]
            )
            adopted = item["ppid"] == os.getpid()
            if inherited or adopted:
                try:
                    handle = os.pidfd_open(pid)
                except ProcessLookupError:
                    continue
                try:
                    again = status(pid)
                except (FileNotFoundError, ProcessLookupError):
                    os.close(handle)
                    continue
                if again["startTicks"] != item["startTicks"]:
                    os.close(handle)
                    raise RuntimeError("Owned PID changed while opening its pidfd")
                if len(owned) >= 64 or len(history) >= 4096:
                    # Reject excess work without retaining an unbounded identity list.
                    # Its children become adoptable by this dedicated subreaper.
                    protocol_invalid = True
                    try:
                        signal.pidfd_send_signal(handle, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    finally:
                        os.close(handle)
                    continue
                owned[pid] = {"startTicks": item["startTicks"], "pidfd": handle}
                history.add((pid, item["startTicks"]))
                detached_observed |= item["pgid"] != group
                changed = True


def living(current):
    return [
        item
        for pid, item in current.items()
        if pid in owned
        and item["startTicks"] == owned[pid]["startTicks"]
        and item["state"] != "Z"
    ]


def terminate(current, kind):
    # Initial process-group signaling never reaches the Python supervisor or unrelated caller.
    members = [
        item
        for item in living(current)
        if item["pgid"] == group and item["sid"] == group
    ]
    if members:
        try:
            os.killpg(group, kind)
        except ProcessLookupError:
            pass
    # Legitimate detached descendants need identity-pinned handles, not a process-name kill.
    for item in living(current):
        if item["pgid"] != group:
            try:
                signal.pidfd_send_signal(owned[item["pid"]]["pidfd"], kind)
            except ProcessLookupError:
                pass


try:
    process = subprocess.Popen(
        [configuration["node"], configuration["bridge"]],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={"LANG": "C.UTF-8", "TZ": "UTC", "NODE_ENV": "test"},
    )
    group = process.pid
    assert group != os.getpgrp()
    root = status(group)
    assert root["pgid"] == group and root["sid"] == group
    owned[group] = {"startTicks": root["startTicks"], "pidfd": os.pidfd_open(group)}
    history.add((group, root["startTicks"]))
    os.set_blocking(process.stdin.fileno(), False)
    selector.register(process.stdin, selectors.EVENT_WRITE)
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    while True:
        now = time.monotonic()
        for key, _ in selector.select(timeout=configuration["sampleIntervalMs"] / 1000):
            if key.fileobj is process.stdin:
                if interrupted:
                    selector.unregister(process.stdin)
                    process.stdin.close()
                    continue
                try:
                    count = os.write(process.stdin.fileno(), pending_input[:65536])
                    transferred += count
                    pending_input = pending_input[count:]
                except BlockingIOError:
                    continue
                except BrokenPipeError:
                    protocol_invalid = True
                    pending_input = pending_input[:0]
                if not pending_input:
                    selector.unregister(process.stdin)
                    process.stdin.close()
                continue
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                selector.unregister(key.fileobj)
            elif key.fileobj is process.stdout:
                if len(protocol) + len(chunk) > 2097152:
                    protocol_invalid = True
                elif not protocol_invalid:
                    protocol.extend(chunk)
            else:
                error_bytes += len(chunk)
                if error_bytes > 65536:
                    protocol_invalid = True
        current = snapshot()
        discover(current)
        live = living(current)
        rss = []
        for item in live:
            try:
                rollup = (Path("/proc") / str(item["pid"]) / "smaps_rollup").read_text()
                rss.append(
                    int(
                        next(
                            line.split()[1]
                            for line in rollup.splitlines()
                            if line.startswith("Rss:")
                        )
                    )
                    * 1024
                )
            except (FileNotFoundError, ProcessLookupError):
                rss_vanished += 1
            except (OSError, ValueError, StopIteration):
                rss_inaccessible += 1
        sampling_rounds += 1
        assert sampling_rounds <= 10000
        max_concurrent = max(max_concurrent, len(live))
        rss_peak = max(rss_peak, sum(rss))
        rss_single_peak = max([rss_single_peak, *rss])
        max_sampling_gap = max(max_sampling_gap, now - last_sample)
        last_sample = now
        no_children = False
        while True:
            try:
                pid, code, usage = os.wait4(-1, os.WNOHANG)
            except ChildProcessError:
                no_children = True
                break
            if pid == 0:
                break
            reaped_count += 1
            user_cpu += usage.ru_utime
            system_cpu += usage.ru_stime
            largest_rss = max(largest_rss, usage.ru_maxrss * 1024)
            if pid == group:
                root_reaped = True
                process.returncode = os.waitstatus_to_exitcode(code)
        expired = now - began >= configuration["timeoutMs"] / 1000
        failed_root = root_reaped and process.returncode != 0
        terminate_requested = expired or interrupted or protocol_invalid or failed_root
        if terminate_requested and term_at is None:
            terminate(current, signal.SIGTERM)
            term_at = now
        if (
            term_at is not None
            and now - term_at >= configuration["cleanupGraceMs"] / 1000
            and live
        ):
            terminate(current, signal.SIGKILL)
        if root_reaped and no_children and not living(snapshot()):
            break
        assert (
            now - began
            < (configuration["timeoutMs"] + configuration["cleanupGraceMs"]) / 1000 + 3
        )
    for stream in [process.stdout, process.stderr]:
        chunk = stream.read(2097153)
        if stream is process.stdout:
            if len(protocol) + len(chunk) > 2097152:
                protocol_invalid = True
            else:
                protocol.extend(chunk)
        else:
            error_bytes += len(chunk)
    remaining = living(snapshot())
    assert not remaining
    resource = {
        "scope": "whole-supervised-lifecycle",
        "elapsedMs": (time.monotonic() - began) * 1000,
        "userCpuSeconds": user_cpu,
        "systemCpuSeconds": system_cpu,
        "largestSingleProcessRssBytes": largest_rss,
        "sampledSummedRssPeakBytes": rss_peak,
        "sampledLargestSingleRssBytes": rss_single_peak,
        "rssReadQuality": {
            "inaccessibleReads": rss_inaccessible,
            "vanishedBeforeRead": rss_vanished,
            "allObservedReadsAccessible": rss_inaccessible == 0,
        },
        "samplingRounds": sampling_rounds,
        "descendantDiscoveryQuality": discovery_quality,
        "inputBytesTransferred": transferred,
        "inputBytesTotal": len(encoded),
        "maxSamplingGapMs": max_sampling_gap * 1000,
        "peakConcurrentProcesses": max_concurrent,
        "observedPids": sorted({pid for pid, _ in history}),
        "observedProcessCount": len(history),
        "detachedProcessObserved": detached_observed,
        "reapedProcessCount": reaped_count,
        "remainingOwnedProcesses": 0,
        "allChildrenWaited": True,
        "pythonObserverIncluded": False,
        "externalServerResourcesIncluded": False,
    }
    outcome = (
        "aborted"
        if interrupted
        else "timeout" if term_at is not None and expired else "failed"
    )
    result = None
    if (
        term_at is None
        and process.returncode == 0
        and not protocol_invalid
        and not error_bytes
    ):
        try:
            result = json.loads(protocol)
            assert set(result) == {"resultBase64"} and isinstance(
                result["resultBase64"], str
            )
            assert (
                len(result["resultBase64"])
                <= (configuration["maxMessageBytes"] + 2) // 3 * 4
            )
            outcome = "completed"
        except (ValueError, AssertionError, TypeError):
            outcome = "failed"
    print(
        json.dumps(
            {
                "status": outcome,
                "resource": resource,
                **(result if outcome == "completed" else {}),
            }
        ),
        flush=True,
    )
finally:
    cleanup = time.monotonic() + 2
    cleaned = False
    while time.monotonic() < cleanup:
        current = snapshot()
        discover(current)
        terminate(current, signal.SIGKILL)
        try:
            pid, _, _ = os.wait4(-1, os.WNOHANG)
            if pid == 0:
                time.sleep(0.01)
        except ChildProcessError:
            cleaned = True
            break
    selector.close()
    for item in owned.values():
        os.close(item["pidfd"])
    assert cleaned, "Owned benchmark descendants did not finish cleanup"
