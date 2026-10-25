# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Prepare private etcd mTLS identities and isolated disposable data directories."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
from urllib.parse import urlencode


IMAGE = "gcr.io/etcd-development/etcd:v3.7.3@sha256:0d27b9478551f431f82d1e0ddb6c87ad07ebae8b904c637f3a99213349523910"


def run(*arguments):
    subprocess.run(arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def private_file(path, content):
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        output.write(content)


def prepare(directory, github_environment=None):
    directory = directory.resolve()
    if "\n" in str(directory) or "\r" in str(directory):
        raise ValueError("The fixture directory must fit on one environment line")
    for parent in (directory, *directory.parents):
        if (parent / ".git").exists():
            raise ValueError("etcd fixture identities must stay outside a Git checkout")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous_mask = os.umask(0o077)
    try:
        prefix = "/arkeniva_test_" + secrets.token_hex(12) + "/"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=ArkenivaJS disposable etcd CA",
            "-keyout", str(directory / "ca.key"), "-out", str(directory / "ca.crt"))
        identities = (
            ("server", "server", "DNS:localhost,IP:127.0.0.1", "serverAuth"),
            ("wrong-san", "server", "DNS:wrong.invalid", "serverAuth"),
            ("root", "root", None, "clientAuth"),
            ("app", "arkeniva_app", None, "clientAuth"),
            ("probe", "arkeniva_probe", None, "clientAuth"),
            ("unknown", "arkeniva_unknown", None, "clientAuth"),
        )
        for name, common_name, names, usage in identities:
            extensions = "extendedKeyUsage=" + usage + "\n"
            if names:
                extensions += "subjectAltName=" + names + "\n"
            private_file(directory / (name + ".ext"), extensions)
            run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + common_name,
                "-keyout", str(directory / (name + ".key")), "-out", str(directory / (name + ".csr")))
            run("openssl", "x509", "-req", "-days", "3", "-in", str(directory / (name + ".csr")),
                "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"),
                "-set_serial", str(secrets.randbits(128)), "-extfile", str(directory / (name + ".ext")),
                "-out", str(directory / (name + ".crt")))
        # Container health identities and CA copies do not change caller-owned client permissions.
        for source, target in (("ca.crt", "server-ca.crt"), ("probe.crt", "health.crt"), ("probe.key", "health.key")):
            private_file(directory / target, (directory / source).read_text(encoding="utf-8"))
        owned = [directory / name for name in (
            "server.key", "server.crt", "wrong-san.key", "wrong-san.crt", "server-ca.crt", "health.crt", "health.key",
        )]
        for name in ("data-server", "data-wrong-san"):
            path = directory / name
            path.mkdir(mode=0o700)
            owned.append(path)
        run("sudo", "-n", "chown", "65532:65532", *map(str, owned))

        def endpoint(port, role="app"):
            query = urlencode({"sslca": str(directory / "ca.crt"), "sslcert": str(directory / (role + ".crt")),
                               "sslkey": str(directory / (role + ".key")), "prefix": prefix})
            return f"https://localhost:{port}?{query}"

        environment = {
            "ETCD_FIXTURE_DIRECTORY": str(directory), "ARKENIVA_ETCD_IMAGE": IMAGE,
            "ARKENIVA_ETCD_DISPOSABLE": "1", "ARKENIVA_ETCD_PREFIX": prefix,
            "ARKENIVA_ETCD_URL": endpoint(12379), "ARKENIVA_ETCD_WRONG_SAN_URL": endpoint(12380),
            "ARKENIVA_ETCD_CONTROL_URL": endpoint(12379, "root"),
            "ARKENIVA_ETCD_UNKNOWN_IDENTITY_URL": endpoint(12379, "unknown"),
        }
        private_file(directory / "environment.json", json.dumps(environment) + "\n")
        if github_environment:
            with github_environment.open("a", encoding="utf-8") as output:
                for key, value in environment.items():
                    output.write(key + "=" + value + "\n")
    finally:
        os.umask(previous_mask)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--github-env", type=Path)
    arguments = parser.parse_args()
    prepare(arguments.directory, arguments.github_env)
