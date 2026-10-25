"""Prepare private disposable NATS identities and independently healthy TLS endpoints."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
from urllib.parse import urlencode


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
            raise ValueError("NATS fixture identities must stay outside a Git checkout")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous_mask = os.umask(0o077)
    try:
        passwords = {role: secrets.token_hex(32) for role in ("alpha", "beta")}
        namespace = "arkeniva_" + secrets.token_hex(12) + "."
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=ArkenivaJS disposable NATS CA",
            "-keyout", str(directory / "ca.key"), "-out", str(directory / "ca.crt"))
        for name, extensions in (
            ("server", "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"),
            ("wrong-san", "subjectAltName=DNS:wrong.invalid\nextendedKeyUsage=serverAuth\n"),
            ("client", "subjectAltName=DNS:disposable-client\nextendedKeyUsage=clientAuth\n"),
        ):
            private_file(directory / (name + ".ext"), extensions)
            run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
                "-keyout", str(directory / (name + ".key")), "-out", str(directory / (name + ".csr")))
            run("openssl", "x509", "-req", "-days", "3", "-in", str(directory / (name + ".csr")),
                "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"),
                "-set_serial", str(secrets.randbits(128)), "-extfile", str(directory / (name + ".ext")),
                "-out", str(directory / (name + ".crt")))
        configuration = {
            "listen": "0.0.0.0:4222",
            "http": "127.0.0.1:8222",
            "server_name": "disposable-nats",
            "max_connections": 128,
            "max_subscriptions": 64,
            "max_payload": 1048576,
            "max_pending": 8388608,
            "max_control_line": 4096,
            "write_deadline": "2s",
            "debug": False,
            "trace": False,
            "tls": {
                "cert_file": "/fixture/server.crt",
                "key_file": "/fixture/server.key",
                "ca_file": "/fixture/ca.crt",
                "verify": True,
                "handshake_first": True,
                "timeout": 2,
            },
            "authorization": {
                "timeout": 2,
                "users": [
                    {
                        "user": "arkeniva_" + role,
                        "password": password,
                        "permissions": {
                            "publish": {"allow": [namespace + role + ".>"]},
                            "subscribe": {"allow": [namespace + role + ".>"]},
                        },
                    }
                    for role, password in passwords.items()
                ],
            },
        }
        private_file(directory / "nats.conf", json.dumps(configuration) + "\n")
        private_file(directory / "server-ca.crt", (directory / "ca.crt").read_text(encoding="utf-8"))
        owned = [directory / name for name in (
            "server.key", "server.crt", "wrong-san.key", "wrong-san.crt", "server-ca.crt", "nats.conf",
        )]
        if os.getuid() != 1000:
            run("sudo", "-n", "chown", "1000:1000", *map(str, owned))

        def endpoint(port, role="alpha"):
            query = urlencode({
                "caFile": str(directory / "ca.crt"),
                "certFile": str(directory / "client.crt"),
                "keyFile": str(directory / "client.key"),
                "prefix": namespace + role + ".",
            })
            return f"tls://arkeniva_{role}:{passwords[role]}@localhost:{port}?{query}"

        environment = {
            "NATS_FIXTURE_DIRECTORY": str(directory),
            "ARKENIVA_NATS_IMAGE": "nats:2.15.1-alpine@sha256:7ae34c25dfd6fe2e01c6483eabef20d796690fdcac6c4d94ca780a6cf9877fde",
            "ARKENIVA_NATS_DISPOSABLE": "1",
            "ARKENIVA_NATS_URL": endpoint(14223),
            "ARKENIVA_NATS_BETA_URL": endpoint(14223, "beta"),
            "ARKENIVA_NATS_WRONG_SAN_URL": endpoint(14224),
        }
        private_file(directory / "environment.json", json.dumps(environment) + "\n")
        if github_environment:
            for password in passwords.values():
                print("::add-mask::" + password)
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
