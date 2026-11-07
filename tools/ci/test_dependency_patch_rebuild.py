# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Exercise the pinned pnpm patch engine without network or native compilation.

The positive fixtures use the real compatibility patches and synthetic inert
preimages: only context/deletion lines come from upstream code; unknown gaps are
sentinels. Package metadata is replaced with a dependency-free, inert lifecycle.
This checks actual install/rebuild idempotence, not upstream payload equivalence.
"""

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATCHES = (
    "packages/messaging-kafka/compat/confluent-exact-offsets-and-build.diff",
    "packages/realtime/compat/fastify-sse-bounded-output.diff",
    "packages/security-scim/compat/scimmy-replacement-and-empty-page.diff",
)
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def safe_path(value):
    if value == "/dev/null":
        return None
    value = value.split("\t", 1)[0]
    path = PurePosixPath(value)
    if len(path.parts) < 2 or path.parts[0] not in {"a", "b"} or ".." in path.parts:
        raise ValueError("The compatibility patch contains an unsafe fixture path")
    return PurePosixPath(*path.parts[1:]).as_posix()


def project_preimages(text):
    """Keep real hunks; reconstruct their preimage data without applying them."""
    preimages, targets, selected = {}, set(), []
    blocks = re.split(r"(?=^diff --git )", text, flags=re.M)
    for block in blocks:
        if not block:
            continue
        lines = block.splitlines(keepends=True)
        old = next((safe_path(x[4:].rstrip("\n")) for x in lines if x.startswith("--- ")), None)
        new = next((safe_path(x[4:].rstrip("\n")) for x in lines if x.startswith("+++ ")), None)
        if old == "package.json" or new == "package.json":
            continue
        hunks = []
        for index, line in enumerate(lines):
            match = HUNK.match(line)
            if match:
                hunks.append((index, int(match[1]), int(match[2] or "1")))
        if not hunks:
            raise ValueError("Fixture patch sections require inspectable text hunks")
        selected.append(block)
        targets.update(x for x in (old, new) if x is not None)
        if old is None:
            continue
        end = max(start - 1 + count for _, start, count in hunks)
        if not 0 <= end <= 100000:
            raise ValueError("Compatibility preimage exceeds its line bound")
        values = ["// Inert preimage gap " + str(i) + "\n" for i in range(end + 2)]
        assigned = {}
        for number, (begin, start, count) in enumerate(hunks):
            stop = hunks[number + 1][0] if number + 1 < len(hunks) else len(lines)
            source = []
            for line in lines[begin + 1:stop]:
                if line.startswith("\\ No newline"):
                    raise ValueError("The fixture requires explicit final-newline handling")
                if line.startswith((" ", "-")):
                    source.append(line[1:])
                elif line == "\n":
                    source.append(line)
                elif not line.startswith("+"):
                    raise ValueError("Unexpected compatibility hunk data")
            if len(source) != count:
                raise ValueError("Compatibility hunk preimage count is inconsistent")
            for offset, value in enumerate(source, start - 1):
                if offset in assigned and assigned[offset] != value:
                    raise ValueError("Overlapping hunks disagree about their preimage")
                values[offset] = value
                assigned[offset] = value
        preimages[old] = "".join(values).encode()
    if not selected or sum(map(len, preimages.values())) > 8 * 1024 * 1024:
        raise ValueError("Compatibility fixtures must be nonempty and bounded")
    return preimages, sorted(targets), "".join(selected)


def snapshot(directory, targets):
    result = {}
    for name in targets:
        path = directory / name
        if path.exists():
            if not path.is_file() or path.is_symlink():
                raise ValueError("Patch probe targets must remain regular files")
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def run_case(base, pnpm, manager, label, preimages, targets, patch, negative=False):
    case = base / label
    case.mkdir()
    name = "inert-patch-probe-" + label
    metadata = {"name": name, "version": "1.0.0", "scripts": {"postinstall": "node -e \"process.exit(0)\""}}
    archive = case / "fixture.tgz"
    with tarfile.open(archive, "w:gz") as packed:
        for path, data in {"package.json": (json.dumps(metadata) + "\n").encode(), **preimages}.items():
            info = tarfile.TarInfo("package/" + path)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            packed.addfile(info, io.BytesIO(data))
    (case / "fixture.diff").write_text(patch)
    (case / "package.json").write_text(json.dumps({
        "name": "private-" + name, "version": "1.0.0", "private": True,
        "packageManager": manager,
        "dependencies": {name: "file:./fixture.tgz"},
    }) + "\n")
    (case / "pnpm-workspace.yaml").write_text(
        "patchedDependencies:\n  " + json.dumps(name + "@1.0.0") + ": fixture.diff\n"
        "allowBuilds:\n  " + json.dumps(name + "@file:fixture.tgz") + ": true\n"
    )
    home = case / "home"
    home.mkdir()
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(home),
        "LANG": "C.UTF-8", "TZ": "UTC", "NO_COLOR": "1",
        "COREPACK_ENABLE_NETWORK": "0", "PNPM_CONFIG_UPDATE_NOTIFIER": "false",
        "PNPM_CONFIG_PM_ON_FAIL": "ignore",
        "PNPM_CONFIG_STORE_DIR": str(case / "store"),
        "PNPM_CONFIG_CACHE_DIR": str(case / "cache"),
        "PNPM_CONFIG_STATE_DIR": str(case / "state"),
        "PNPM_CONFIG_CONFIG_DIR": str(case / "config"),
        "PNPM_CONFIG_REGISTRY": "https://registry.invalid/",
    }
    corepack = os.environ.get("COREPACK_HOME")
    if corepack:
        env["COREPACK_HOME"] = corepack
    else:
        cached = Path.home() / ".cache/node/corepack"
        if cached.is_dir():
            env["COREPACK_HOME"] = str(cached)

    # The fixture pins Corepack, while this exact check replaces pnpm's online boot resolution.
    version = subprocess.check_output([pnpm, "--version"], cwd=case, env=env,
                                      text=True, timeout=60).strip()
    if version != manager.removeprefix("pnpm@"):
        raise ValueError("The private fixture must execute the exact reviewed pnpm version")

    def invoke(*args):
        result = subprocess.run([pnpm, *args], cwd=case, env=env,
                                capture_output=True, timeout=60)
        if result.returncode:
            diagnostics = (result.stdout + result.stderr)[-65536:].decode(errors="replace")
            raise RuntimeError("Pinned pnpm probe failed: " + label + "\n" + diagnostics)

    invoke("install", "--offline", "--ignore-scripts", "--store-dir", str(case / "store"))
    installed = (case / "node_modules" / name).resolve(strict=True)
    if not installed.is_relative_to(case):
        raise ValueError("The local probe escaped its private fixture")
    first = snapshot(installed, targets)
    baseline = {key: hashlib.sha256(value).hexdigest() for key, value in preimages.items()}
    if first == baseline:
        raise AssertionError("Initial fixture install did not apply its compatibility patch")
    invoke("rebuild", name, "--store-dir", str(case / "store"))
    second = snapshot(installed, targets)
    if negative:
        if first == second or (installed / "index.js").read_text().count("const inserted = true;") != 2:
            raise AssertionError("The zero-context control did not expose the pinned engine defect")
        return {"case": label, "zeroContextDuplicateObserved": True}
    if second != first:
        raise AssertionError("A real compatibility patch changed payload during rebuild: " + label)
    invoke("rebuild", name, "--store-dir", str(case / "store"))
    if snapshot(installed, targets) != first:
        raise AssertionError("A second rebuild changed compatibility payload: " + label)
    return {"case": label, "patchedFiles": len(first), "rebuilds": 2, "payloadUnchanged": True}


class DependencyPatchRebuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pnpm = os.environ.get("ARKENIVA_TEST_PNPM") or shutil.which("pnpm")
        if not cls.pnpm:
            raise ValueError("The reviewed pnpm CLI must already be installed")
        cls.manager = json.loads((ROOT / "package.json").read_text())["packageManager"]
        if cls.manager != "pnpm@12.15.0":
            raise ValueError("Review the pinned-engine negative control when upgrading pnpm")
        version = subprocess.check_output([cls.pnpm, "--version"], cwd=ROOT, text=True).strip()
        if version != cls.manager.removeprefix("pnpm@"):
            raise ValueError("The regression requires the repository's actual pinned pnpm CLI")

    def check_patch(self, index):
        relative = PATCHES[index]
        preimages, targets, patch = project_preimages((ROOT / relative).read_text())
        with tempfile.TemporaryDirectory(prefix="arkeniva-pnpm-patches-") as temporary:
            base = Path(temporary).resolve()
            self.assertFalse(base.is_relative_to(ROOT), "Keep fixtures outside source")
            result = run_case(base, self.pnpm, self.manager, "compat-" + str(index),
                              preimages, targets, patch)
        result["actualPatch"] = relative
        result["patchSha256"] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        print(json.dumps(result))

    def test_zero_context_control_exposes_duplicate(self):
        with tempfile.TemporaryDirectory(prefix="arkeniva-pnpm-patches-") as temporary:
            result = run_case(Path(temporary).resolve(), self.pnpm, self.manager, "zero-context",
                              {"index.js": b"const before = true;\nconst after = true;\n"},
                              ["index.js"], "diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1,0 +2 @@\n+const inserted = true;\n",
                              negative=True)
        print(json.dumps(result))

    def test_kafka_patch_payload_survives_rebuild(self):
        self.check_patch(0)

    def test_realtime_patch_payload_survives_rebuild(self):
        self.check_patch(1)

    def test_scim_patch_payload_survives_rebuild(self):
        self.check_patch(2)


if __name__ == "__main__":
    unittest.main()
