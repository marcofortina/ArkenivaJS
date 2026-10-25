# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Inspect built package archives without extracting files or publishing packages."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
LICENSE_SHA256 = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_CONTENT_BYTES = 128 * 1024 * 1024
FORBIDDEN_COMPONENTS = {"src", "test", "tests", "dist-test", "node_modules", ".git"}
ROOT_FILES = {"package.json", "README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md"}


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def inspect_archive(archive, location, manifest, workspace_versions, license_bytes):
    """Reject unexpected paths, altered content and unresolved dependency references."""
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Package archive exceeds the inspection size limit")
    if sha256(license_bytes) != LICENSE_SHA256:
        raise ValueError("Root LICENSE differs from the reviewed upstream text")
    declared = set(manifest["files"])
    if not declared <= {"dist", "compat", *ROOT_FILES}:
        raise ValueError("Package file allowlist requires an explicit content review")
    contents, total = {}, 0
    with tarfile.open(archive, "r:gz") as packed:
        for member in packed:
            path = PurePosixPath(member.name)
            if (not member.isfile() or path.is_absolute() or ".." in path.parts
                    or len(path.parts) < 2 or path.parts[0] != "package"
                    or path.as_posix() != member.name or "\\" in member.name
                    or member.name in contents):
                raise ValueError("Package archive contains an unsafe or duplicate entry")
            relative = PurePosixPath(*path.parts[1:])
            if FORBIDDEN_COMPONENTS.intersection(relative.parts):
                raise ValueError("Package archive contains source, tests or private build material")
            if any(part.startswith(".") for part in relative.parts):
                raise ValueError("Package archive contains hidden configuration")
            allowed = relative.as_posix() in {"package.json", "LICENSE", "README.md"} or relative.as_posix() in declared.intersection(ROOT_FILES)
            if relative.parts[0] in {"dist", "compat"}:
                allowed = relative.parts[0] in declared and len(relative.parts) > 1
            if not allowed:
                raise ValueError("Package archive contains an undeclared product file")
            if relative.parts[0] == "dist" and not relative.name.endswith((".js", ".d.ts", ".map")):
                raise ValueError("Package archive contains an unexpected compiled file format")
            if relative.parts[0] == "dist":
                source = re.sub(r"(?:\.js|\.d\.ts)(?:\.map)?$", ".ts", str(PurePosixPath(*relative.parts[1:])))
                if not source.endswith(".ts") or not (location / "src" / source).is_file():
                    raise ValueError("Package archive contains a stale or unowned compiled artifact")
            if len(contents) >= 10000:
                raise ValueError("Package archive exceeds the file count limit")
            total += member.size
            if member.size < 0 or total > MAX_CONTENT_BYTES:
                raise ValueError("Package archive exceeds the expanded inspection size limit")
            payload = packed.extractfile(member).read(member.size + 1)
            if len(payload) != member.size:
                raise ValueError("Package archive contains truncated content")
            if relative.as_posix() != "package.json":
                expected = license_bytes if relative.as_posix() == "LICENSE" else (location / str(relative)).read_bytes()
                if payload != expected:
                    raise ValueError("Packed product bytes differ from the inspected build")
            if re.search(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----", payload):
                raise ValueError("Package archive contains private key material")
            contents[member.name] = {"bytes": len(payload), "sha256": sha256(payload)}
            if relative.as_posix() == "package.json":
                metadata = json.loads(payload)
    required = {"package/" + name for name in ["package.json", "README.md", "CHANGELOG.md", "LICENSE"]}
    required |= {"package/" + name for name in declared if name in ROOT_FILES}
    if (location / "THIRD_PARTY_NOTICES.md").is_file():
        required.add("package/THIRD_PARTY_NOTICES.md")
    if not required <= contents.keys():
        raise ValueError("Package archive omitted required documentation or legal notices")
    for key in ["name", "version", "type", "exports", "engines", "license", "private"]:
        if metadata.get(key) != manifest.get(key):
            raise ValueError("Packed metadata differs from the reviewed package manifest: " + key)
    if metadata.get("private") is not True or metadata.get("license") != "AGPL-3.0-or-later":
        raise ValueError("Unapproved publishing state or package license")
    for scope in ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]:
        for name, reference in metadata.get(scope, {}).items():
            expected = manifest[scope][name]
            if expected.startswith("workspace:"):
                if expected != "workspace:*" or reference != workspace_versions.get(name):
                    raise ValueError("Packed workspace dependency is unresolved or has a wrong version")
            elif reference != expected:
                raise ValueError("Packed dependency differs from the reviewed exact reference")
            if reference.startswith(("workspace:", "file:", "link:")):
                raise ValueError("Package archive contains a local dependency reference")
        if set(metadata.get(scope, {})) != set(manifest.get(scope, {})):
            raise ValueError("Packed dependency inventory differs from the source manifest")
    for conditions in metadata["exports"].values():
        if not isinstance(conditions, dict) or set(conditions) != {"types", "import"}:
            raise ValueError("Package exports require a reviewed ESM and declaration pair")
        for target in conditions.values():
            if not isinstance(target, str) or not target.startswith("./dist/") or ".." in PurePosixPath(target).parts:
                raise ValueError("Package export points outside the compiled public surface")
            if "package/" + target[2:] not in contents:
                raise ValueError("Package export points to an absent compiled artifact")
    return {"name": manifest["name"], "version": manifest["version"],
            "archive": archive.name, "sha256": sha256(archive.read_bytes()),
            "expandedBytes": total, "files": contents, "private": True}


def create_evidence(destination):
    """Build and pack the clean checkout, retaining private evidence outside Git."""
    if not destination.is_absolute() or not destination.name:
        raise ValueError("Package evidence requires a fresh absolute destination")
    output = destination.parent.resolve(strict=True) / destination.name
    if any((parent / ".git").exists() for parent in [output.parent, *output.parent.parents]):
        raise ValueError("Package evidence must remain outside Git")
    git = lambda *args: subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    revision = git("rev-parse", "HEAD")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Package evidence requires a clean checkout")
    root_manifest = json.loads((ROOT / "package.json").read_text())
    package_manager = subprocess.check_output(["pnpm", "--version"], cwd=ROOT, text=True).strip()
    if root_manifest["packageManager"] != "pnpm@" + package_manager:
        raise ValueError("Package evidence requires the exact reviewed package manager")
    manifests = [(path.parent, json.loads(path.read_text())) for path in sorted((ROOT / "packages").glob("*/package.json"))]
    versions = {manifest["name"]: manifest["version"] for _, manifest in manifests}
    if not manifests or len(versions) != len(manifests):
        raise ValueError("Package evidence requires a nonempty set of distinct framework packages")
    for _, manifest in manifests:
        if not re.fullmatch(r"@arkenivajs/[a-z][a-z0-9-]*", manifest["name"]):
            raise ValueError("Package identity is outside the reviewed framework scope")
        if manifest["version"] != root_manifest["version"] or manifest.get("private") is not True:
            raise ValueError("Packages must preserve the reviewed private lockstep version")
        if {"prepack", "postpack", "prepare"}.intersection(manifest.get("scripts", {})):
            raise ValueError("Package lifecycle hooks require an explicit execution review")
    output.mkdir(mode=0o700)

    def execute(arguments, filename):
        with (output / filename).open("xb") as log:
            os.chmod(log.name, 0o600)
            result = subprocess.run(arguments, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        if result.returncode != 0:
            raise ValueError("Package verification failed; inspect the private command log")

    execute(["pnpm", "build"], "build.log")
    results = []
    license_bytes = (ROOT / "LICENSE").read_bytes()
    for index, (location, manifest) in enumerate(manifests):
        execute(["pnpm", "--filter", manifest["name"], "pack", "--pack-destination", str(output)],
                "pack-" + str(index) + ".log")
        archive = output / (manifest["name"].replace("@", "").replace("/", "-") + "-" + manifest["version"] + ".tgz")
        archive.chmod(0o600)
        results.append(inspect_archive(archive, location, manifest, versions, license_bytes))
    if git("rev-parse", "HEAD") != revision or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Source changed during package verification")
    report = {"formatVersion": 1, "revision": revision, "packageManager": root_manifest["packageManager"],
              "publicationAuthorized": False, "packages": results}
    with (output / "packages.json").open("x") as target:
        os.chmod(target.name, 0o600)
        json.dump(report, target, indent=2)
        target.write("\n")
    print("Verified actual contents, exports and legal notices in", len(results), "private package archives.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    create_evidence(parser.parse_args().destination)
