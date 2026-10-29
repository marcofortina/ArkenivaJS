# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Own a private production-file fixture on an explicitly disposable Linux runner."""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys


def identity(root, uid, gid, nonce):
    if (not re.fullmatch(r"/run/arkenivajs-tenant-file-[0-9a-f]{24}", str(root))
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or not 0 < uid < 2**31 or not 0 < gid < 2**31):
        raise ValueError("Invalid disposable fixture identity")
    return {"uid": uid, "gid": gid, "nonce": nonce}


def prepare(root, uid, gid, nonce):
    marker = identity(root, uid, gid, nonce)
    if os.getuid() != 0 or root.exists() or root.is_symlink():
        raise ValueError("Fixture preparation requires a new root-owned deployment")
    root.mkdir(mode=0o750)
    os.chown(root, 0, gid)
    (root / ".fixture.json").write_text(json.dumps(marker), encoding="utf8")
    os.chmod(root / ".fixture.json", 0o600)
    # This fixed ASCII/empty-array vector is already in RFC 8785 key order.
    canonical = b'{"bindings":[],"implementations":[],"operations":[],"schemaVersion":"1.1.0"}'
    value = {**json.loads(canonical), "revision": "isolated-deployment",
             "activationGeneration": 1, "activatedAt": "2026-01-01T00:00:00.000Z",
             "contentChecksum": "sha256:" + hashlib.sha256(canonical).hexdigest()}
    for name, owner, mode in [("valid.json", 0, 0o640), ("public.json", 0, 0o644),
                              ("untrusted-owner.json", uid, 0o600)]:
        file = root / name
        file.write_text(json.dumps(value), encoding="utf8")
        os.chown(file, owner, gid)
        os.chmod(file, mode)
    directory = root / "writable"
    directory.mkdir(mode=0o770)
    os.chown(directory, 0, gid)
    os.chmod(directory, 0o770)
    file = directory / "registry.json"
    file.write_text(json.dumps(value), encoding="utf8")
    os.chown(file, 0, gid)
    os.chmod(file, 0o640)
    (root / "link.json").symlink_to(root / "valid.json")


def cleanup(root, uid, gid, nonce):
    expected = identity(root, uid, gid, nonce)
    marker = root / ".fixture.json"
    if (not root.is_dir() or root.is_symlink() or root.stat().st_uid != 0
            or marker.is_symlink() or not marker.is_file() or marker.stat().st_uid != 0
            or marker.stat().st_size > 256
            or json.loads(marker.read_text(encoding="utf8")) != expected
            or not shutil.rmtree.avoids_symlink_attacks):
        raise ValueError("Refusing cleanup of an unowned fixture")
    shutil.rmtree(root)


def main():
    if os.environ.get("ARKENIVA_TENANT_FILE_DISPOSABLE") != "1":
        raise ValueError("The production file fixture requires an explicitly disposable runner")
    args = sys.argv[1:]
    if args and args[0] in ["--prepare", "--cleanup"]:
        if len(args) != 5 or os.getuid() != 0:
            raise ValueError("Privileged fixture operations require their complete owned identity")
        operation = prepare if args[0] == "--prepare" else cleanup
        operation(Path(args[1]), int(args[2]), int(args[3]), args[4])
        return 0
    if os.getuid() == 0 or not args or args[0] != "--" or len(args) < 2:
        raise ValueError("Run the Node assertion as an unprivileged disposable user")
    uid, gid, nonce = os.getuid(), os.getgid(), secrets.token_hex(16)
    root = Path("/run/arkenivajs-tenant-file-" + secrets.token_hex(12))
    identity(root, uid, gid, nonce)
    privileged = ["sudo", "-n", "env", "ARKENIVA_TENANT_FILE_DISPOSABLE=1",
                  sys.executable, str(Path(__file__).resolve())]
    values = [str(root), str(uid), str(gid), nonce]
    subprocess.run([*privileged, "--prepare", *values], check=True)
    try:
        return subprocess.run(args[1:], env={**os.environ, "ARKENIVA_TENANT_FILE_ROOT": str(root)}, check=False).returncode
    finally:
        subprocess.run([*privileged, "--cleanup", *values], check=True)


if __name__ == "__main__":
    raise SystemExit(main())
