# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Enable scoped etcd certificate authentication on an explicitly disposable fixture."""

import argparse
import json
import os
from pathlib import Path
import subprocess


def bootstrap(directory):
    path = directory / "environment.json"
    if path.stat().st_mode & 0o077:
        raise ValueError("The fixture environment must remain private")
    environment = json.loads(path.read_text(encoding="utf-8"))
    if environment.get("ARKENIVA_ETCD_DISPOSABLE") != "1":
        raise ValueError("Only a disposable etcd fixture can be initialized")
    prefix = environment["ARKENIVA_ETCD_PREFIX"]
    for host, port in (("localhost", 12379), ("wrong.invalid", 12380)):
        base = ["docker", "run", "--rm", "--network", "host", "--user", f"{os.getuid()}:{os.getgid()}",
                "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                "--add-host", "wrong.invalid:127.0.0.1"]
        for source, target in (("ca.crt", "ca.crt"), ("root.crt", "client.crt"), ("root.key", "client.key")):
            base.extend(["--mount", f"type=bind,source={directory / source},target=/bootstrap/{target},readonly"])
        base.extend(["--entrypoint", "/usr/local/bin/etcdctl", environment["ARKENIVA_ETCD_IMAGE"],
                     f"--endpoints=https://{host}:{port}", "--cacert=/bootstrap/ca.crt",
                     "--cert=/bootstrap/client.crt", "--key=/bootstrap/client.key",
                     "--dial-timeout=5s", "--command-timeout=5s"])

        def call(*arguments):
            subprocess.run([*base, *arguments], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # The server never mounts the root identity; this one-shot client performs initialization.
        call("user", "add", "root", "--no-password")
        call("user", "grant-role", "root", "root")
        call("role", "add", "arkeniva_app")
        call("role", "grant-permission", "arkeniva_app", "readwrite", prefix, "--prefix=true")
        call("user", "add", "arkeniva_app", "--no-password")
        call("user", "grant-role", "arkeniva_app", "arkeniva_app")
        call("role", "add", "arkeniva_probe")
        call("role", "grant-permission", "arkeniva_probe", "read", "health")
        call("user", "add", "arkeniva_probe", "--no-password")
        call("user", "grant-role", "arkeniva_probe", "arkeniva_probe")
        call("auth", "enable")
    print("Disposable etcd certificate authentication and scoped roles are enabled")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    bootstrap(arguments.directory.resolve())
