# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Prepare private MongoDB TLS, SCRAM and replica-set fixture material outside Git."""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
from urllib.parse import quote, urlencode


IMAGE = "mongo:9.0.4@sha256:dc28ed5a9d0fc616903c3f463bb1e53b92b49f441721b91926e87d90bf957ce8"


def run(*arguments):
    subprocess.run(arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def private_file(path, content):
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        output.write(content)


def prepare(directory, github_environment=None):
    directory = directory.resolve()
    if "\n" in str(directory) or "\r" in str(directory):
        raise ValueError("The fixture path must fit on one environment line")
    for parent in (directory, *directory.parents):
        if (parent / ".git").exists():
            raise ValueError("MongoDB fixture material must stay outside every Git checkout")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous_mask = os.umask(0o077)
    try:
        database = "arkeniva_test_" + secrets.token_hex(12)
        credentials = {
            "database": database,
            "root": {"username": "arkeniva_control", "password": secrets.token_urlsafe(36)},
            "app": {"username": "arkeniva_app", "password": secrets.token_urlsafe(36)},
            "probe": {"username": "arkeniva_probe", "password": secrets.token_urlsafe(36)},
        }
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=ArkenivaJS disposable MongoDB CA", "-keyout", str(directory / "ca.key"),
            "-out", str(directory / "ca.crt"))
        for name, names in (("server", "DNS:localhost,IP:127.0.0.1"), ("wrong-san", "DNS:wrong.invalid")):
            private_file(directory / (name + ".ext"), "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=" + names + "\n")
            run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
                "-keyout", str(directory / (name + ".key")), "-out", str(directory / (name + ".csr")))
            run("openssl", "x509", "-req", "-days", "3", "-in", str(directory / (name + ".csr")),
                "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"),
                "-set_serial", str(secrets.randbits(128)), "-extfile", str(directory / (name + ".ext")),
                "-out", str(directory / (name + ".crt")))
            private_file(directory / (name + ".pem"), (directory / (name + ".key")).read_text() + (directory / (name + ".crt")).read_text())
        private_file(directory / "server-ca.crt", (directory / "ca.crt").read_text())
        private_file(directory / "replica.key", base64.b64encode(secrets.token_bytes(512)).decode() + "\n")
        private_file(directory / "bootstrap.json", json.dumps(credentials) + "\n")
        private_file(directory / "health.json", json.dumps(credentials["probe"]) + "\n")
        owned = [directory / name for name in ("server.pem", "wrong-san.pem", "server-ca.crt", "replica.key", "health.json")]
        for name in ("data-server", "data-wrong-san"):
            path = directory / name
            path.mkdir(mode=0o700)
            owned.append(path)
        run("sudo", "-n", "chown", "999:999", *map(str, owned))

        def endpoint(port, role="app"):
            identity = credentials[role]
            parameters = {"tls": "true", "tlsCAFile": str(directory / "ca.crt"),
                          "authSource": "admin" if role == "root" else database,
                          "directConnection": "true", "replicaSet": "arkeniva"}
            if role == "app":
                parameters["prefix"] = "app_"
            return ("mongodb://" + quote(identity["username"], safe="") + ":" + quote(identity["password"], safe="")
                    + f"@localhost:{port}/{database}?" + urlencode(parameters))

        environment = {
            "MONGODB_FIXTURE_DIRECTORY": str(directory), "ARKENIVA_MONGODB_IMAGE": IMAGE,
            "ARKENIVA_MONGODB_DISPOSABLE": "1", "ARKENIVA_MONGODB_DATABASE": database,
            "ARKENIVA_MONGODB_URL": endpoint(27018), "ARKENIVA_MONGODB_WRONG_SAN_URL": endpoint(27019),
            "ARKENIVA_MONGODB_CONTROL_URL": endpoint(27018, "root"),
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
