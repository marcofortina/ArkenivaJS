# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Scan a clean repository's complete history in a restricted disposable container."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import re

IMAGE = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
REVIEWED_VECTOR = "fc0a86f0f54e0fdecb8951944c7065fd454f4245:packages/security-totp/test/unit/service.unit.test.ts:generic-api-key:229"


def reviewed_public_vectors(repository):
    """Validate the owner's single historical public-fixture review, never a path/rule exclusion."""
    relative = "tools/security/reviewed-public-vectors.json"
    path = repository / relative
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ValueError("Public-vector review must be a bounded tracked regular file")
    content = path.read_bytes()
    committed = subprocess.check_output(["git", "show", "HEAD:" + relative], cwd=repository)
    if content != committed:
        raise ValueError("Public-vector review differs from the clean committed policy")
    review = json.loads(content)
    if (not isinstance(review, dict)
            or set(review) != {"standard", "fingerprint", "sourceLineSha256", "reference"}
            or review["fingerprint"] != REVIEWED_VECTOR
            or review["standard"] != "RFC6238-SHA1"
            or review["reference"] != "https://www.rfc-editor.org/rfc/rfc6238.html#appendix-B"):
        raise ValueError("Public-vector policy differs from the exact owner-approved review")
    commit, filename, rule, number = REVIEWED_VECTOR.split(":")
    source = subprocess.check_output(["git", "show", commit + ":" + filename], cwd=repository)
    line = source.decode("utf-8").splitlines()[int(number) - 1]
    match = re.fullmatch(r"\s*secret: '([A-Z2-7]+)',", line)
    if (rule != "generic-api-key" or match is None
            or hashlib.sha256(line.encode("utf-8")).hexdigest() != review["sourceLineSha256"]
            or base64.b32decode(match.group(1)) != b"12345678901234567890"):
        raise ValueError("Reviewed source is not the published RFC6238 SHA1 test vector")
    return [REVIEWED_VECTOR]


def scan(repository, output):
    if os.environ.get("ARKENIVA_SECURITY_DISPOSABLE") != "1":
        raise ValueError("Secret scanning requires an explicitly disposable VM or CI runner")
    repository = repository.resolve(strict=True)
    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], cwd=repository, text=True
    ).strip()
    if Path(root) != repository:
        raise ValueError("The source must be the repository root")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=repository):
        raise ValueError("Full-history evidence requires a clean committed source tree")
    if subprocess.check_output(["git", "rev-parse", "--is-shallow-repository"],
                               cwd=repository, text=True).strip() != "false":
        raise ValueError("Full-history evidence requires a non-shallow checkout")
    reviewed = reviewed_public_vectors(repository)
    output = output.absolute()
    if any(character in str(path) for path in (repository, output)
           for character in (",", "\n", "\r")):
        raise ValueError("Scan paths must not contain container mount delimiters")
    for parent in (output, *output.parents):
        if parent.is_symlink() or (parent / ".git").exists():
            raise ValueError("Secret scan reports require an external path without symlink parents")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous = os.umask(0o077)
    try:
        # Override implicit ignore discovery with only the independently validated immutable fingerprint.
        (output / "reviewed-fingerprints.ignore").write_text(
            "\n".join(reviewed) + ("\n" if reviewed else ""), encoding="utf-8")
        base = [
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "256m", "--cpus", "1", "--pids-limit", "128",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--env", "GIT_CONFIG_COUNT=1", "--env", "GIT_CONFIG_KEY_0=safe.directory",
            "--env", "GIT_CONFIG_VALUE_0=/repository",
            "--mount", f"type=bind,src={repository},dst=/repository,readonly",
            "--mount", f"type=bind,src={output},dst=/reports", IMAGE,
        ]
        version = subprocess.check_output([*base, "version"], text=True, timeout=90).strip()
        if version != "v8.30.1":
            raise ValueError("The secret scanner has an unexpected version")
        started = time.monotonic()
        result = subprocess.run([
            *base, "git", "--log-opts=--all", "--redact=100", "--no-banner",
            "--ignore-gitleaks-allow", "--report-format=json",
            "--gitleaks-ignore-path=/reports/reviewed-fingerprints.ignore",
            "--report-path=/reports/findings.json", "--timeout=180", "/repository",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=210)
        (output / "scanner.log").write_text(result.stdout, encoding="utf-8")
        report = output / "findings.json"
        if report.exists():
            report.chmod(0o600)
        findings = json.loads(report.read_text(encoding="utf-8")) if report.exists() else None
        if findings is not None and not isinstance(findings, list):
            raise ValueError("The secret scanner returned an invalid report")
        status = "PASS" if result.returncode == 0 and findings == [] else "FAIL"
        summary = {
            "status": status, "scanner": version, "image": IMAGE,
            "sourceCommit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repository, text=True
            ).strip(),
            "commits": int(subprocess.check_output(
                ["git", "rev-list", "--count", "--all"], cwd=repository, text=True
            ).strip()),
            "findings": len(findings) if findings is not None else None,
            "reviewedPublicVectorFingerprints": reviewed,
            "exitCode": result.returncode, "durationSeconds": time.monotonic() - started,
            "coverage": "All reachable Git history; clean non-shallow source; upstream detection rules",
            "limitations": "Pattern-based detection is not proof of the absence of every credential",
        }
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary))
        return 0 if status == "PASS" else 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    raise SystemExit(scan(arguments.repository, arguments.output))
