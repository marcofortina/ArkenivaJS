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
    "packages/graphql/compat/typedoc-minimatch-partial.diff",
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
                hunks.append((index, int(match[1]), int(match[2] or "1"),
                              int(match[4] or "1")))
        if not hunks:
            raise ValueError("Fixture patch sections require inspectable text hunks")
        selected.append(block)
        targets.update(x for x in (old, new) if x is not None)
        if old is None:
            continue
        end = max((start - 1 if count else start) + count
                  for _, start, count, _ in hunks)
        if not 0 <= end <= 100000:
            raise ValueError("Compatibility preimage exceeds its line bound")
        values = ["// Inert preimage gap " + str(i) + "\n" for i in range(end + 2)]
        assigned, eof = {}, None
        for number, (begin, start, count, new_count) in enumerate(hunks):
            stop = hunks[number + 1][0] if number + 1 < len(hunks) else len(lines)
            source, new_lines = [], 0
            previous, old_eof, new_eof = None, False, False
            for line in lines[begin + 1:stop]:
                if line.rstrip("\n") == "\\ No newline at end of file":
                    if previous is None:
                        raise ValueError("A final-newline marker must follow hunk data")
                    if previous in {" ", "-"}:
                        if not source[-1].endswith("\n"):
                            raise ValueError("A preimage line cannot lose its newline twice")
                        source[-1] = source[-1][:-1]
                        old_eof = True
                    if previous in {" ", "+"}:
                        new_eof = True
                    previous = None
                    continue
                if line.startswith((" ", "-")):
                    if old_eof:
                        raise ValueError("Preimage data cannot follow its known EOF")
                    source.append(line[1:])
                elif line == "\n":
                    if old_eof:
                        raise ValueError("Preimage data cannot follow its known EOF")
                    source.append(line)
                elif not line.startswith("+"):
                    raise ValueError("Unexpected compatibility hunk data")
                previous = " " if line == "\n" else line[0]
                if previous in {" ", "+"}:
                    if new_eof:
                        raise ValueError("Patched data cannot follow its known EOF")
                    new_lines += 1
            if len(source) != count or new_lines != new_count:
                raise ValueError("Compatibility hunk line count is inconsistent")
            position = start - 1 if count else start
            if old_eof or new_eof:
                # Either side's explicit EOF establishes that no unchanged tail exists.
                current_eof = position + count
                if eof is not None and eof != current_eof:
                    raise ValueError("Compatibility hunks disagree about their known EOF")
                eof = current_eof
            for offset, value in enumerate(source, position):
                if offset in assigned and assigned[offset] != value:
                    raise ValueError("Overlapping hunks disagree about their preimage")
                values[offset] = value
                assigned[offset] = value
        if eof is not None:
            if eof != end:
                raise ValueError("Compatibility hunks extend beyond their known EOF")
            values = values[:eof]
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


class ProjectPreimagesTests(unittest.TestCase):
    def test_known_eof_preserves_each_old_final_newline(self):
        for old_newline, new_newline in [(False, False), (False, True), (True, False)]:
            with self.subTest(old=old_newline, new=new_newline):
                marker = "\\ No newline at end of file\n"
                patch = ("diff --git a/index.js.map b/index.js.map\n"
                         "--- a/index.js.map\n+++ b/index.js.map\n@@ -1 +1 @@\n"
                         '-{"old":true}\n' + ("" if old_newline else marker) +
                         '+{"new":true}\n' + ("" if new_newline else marker))
                preimages, targets, selected = project_preimages(patch)
                self.assertEqual(preimages, {"index.js.map": b'{"old":true}' +
                                             (b"\n" if old_newline else b"")})
                self.assertEqual(targets, ["index.js.map"])
                self.assertEqual(selected, patch)

    def test_unknown_eof_retains_inert_tail(self):
        patch = ("diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n"
                 "@@ -1 +1 @@\n-old\n+new\n")
        preimages, _, _ = project_preimages(patch)
        self.assertEqual(preimages["index.js"],
                         b"old\n// Inert preimage gap 1\n// Inert preimage gap 2\n")

    def test_context_eof_preserves_unterminated_last_line(self):
        patch = ("diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n"
                 "@@ -1,2 +1,2 @@\n-old\n+new\n last\n"
                 "\\ No newline at end of file\n")
        preimages, _, selected = project_preimages(patch)
        self.assertEqual(preimages["index.js"], b"old\nlast")
        self.assertEqual(selected, patch)

    def test_malformed_eof_markers_reject(self):
        header = "diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n"
        marker = "\\ No newline at end of file\n"
        for hunk in [
            "@@ -1 +1 @@\n" + marker + "-old\n+new\n",
            "@@ -1 +1 @@\n-old\n" + marker + marker + "+new\n",
            "@@ -1,2 +1 @@\n-old\n" + marker + "-later\n+new\n",
            "@@ -1 +1,2 @@\n-old\n+new\n" + marker + "+later\n",
            "@@ -1 +1 @@\n-old\n" + marker + "+new\n" + marker +
            "@@ -3 +3 @@\n-later\n+changed\n",
            "@@ -1 +1 @@\n-old\n\\ No newline unknown\n+new\n",
        ]:
            with self.subTest(hunk=hunk), self.assertRaises(ValueError):
                project_preimages(header + hunk)

    def test_known_eof_does_not_relax_preimage_line_bound(self):
        patch = ("diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n"
                 "@@ -100001 +100001 @@\n-old\n\\ No newline at end of file\n"
                 "+new\n\\ No newline at end of file\n")
        with self.assertRaisesRegex(ValueError, "line bound"):
            project_preimages(patch)


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
        if index == 3:
            self.assertEqual(result["patchedFiles"], len(targets),
                             "Every TypeDoc artifact must participate in rebuild snapshots")
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

    def test_typedoc_patch_payload_survives_rebuild(self):
        text = (ROOT / PATCHES[3]).read_text()
        preimages, targets, selected = project_preimages(text)
        expected = {"dist/node-utils.js"}
        self.assertEqual(set(targets), expected)
        self.assertEqual(set(preimages), expected)
        self.assertEqual(selected, text, "Every real TypeDoc hunk must be retained")
        self.check_patch(3)


if __name__ == "__main__":
    unittest.main()
