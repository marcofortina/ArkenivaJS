"""Prepare private, disposable PostgreSQL TLS fixtures outside the checkout."""

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
            raise ValueError("PostgreSQL fixture credentials must stay outside a Git checkout")
    # Refuse reuse: stale data, keys or symbolic links must never enter a new fixture.
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous_mask = os.umask(0o077)
    try:
        password = secrets.token_hex(32)
        private_file(directory / "admin-password", secrets.token_hex(32) + "\n")
        private_file(directory / "init.sql", (
            "CREATE ROLE arkeniva_app LOGIN PASSWORD '" + password + "' "
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;\n"
            "GRANT CONNECT, TEMPORARY, CREATE ON DATABASE arkeniva_test TO arkeniva_app;\n"
        ))
        private_file(directory / "pg_hba.conf", (
            "local all all trust\n"
            "hostssl all all 0.0.0.0/0 scram-sha-256\n"
            "hostssl all all ::/0 scram-sha-256\n"
            "hostnossl all all 0.0.0.0/0 reject\n"
            "hostnossl all all ::/0 reject\n"
        ))
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=ArkenivaJS disposable PostgreSQL CA",
            "-keyout", str(directory / "ca.key"), "-out", str(directory / "ca.crt"))
        for name, identities in (
            ("server", "DNS:localhost,IP:127.0.0.1"),
            ("wrong-san", "DNS:wrong.invalid"),
        ):
            private_file(directory / (name + ".ext"),
                         "subjectAltName=" + identities + "\nextendedKeyUsage=serverAuth\n")
            run("openssl", "req", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=" + name, "-keyout", str(directory / (name + ".key")),
                "-out", str(directory / (name + ".csr")))
            run("openssl", "x509", "-req", "-days", "3",
                "-in", str(directory / (name + ".csr")), "-CA", str(directory / "ca.crt"),
                "-CAkey", str(directory / "ca.key"), "-set_serial", str(secrets.randbits(128)),
                "-extfile", str(directory / (name + ".ext")),
                "-out", str(directory / (name + ".crt")))
        owned = [directory / name for name in (
            "server.key", "server.crt", "wrong-san.key", "wrong-san.crt",
            "admin-password", "init.sql", "pg_hba.conf",
        )]
        for name in ("data-server", "data-wrong-san"):
            path = directory / name
            path.mkdir(mode=0o700)
            owned.append(path)
        # The pinned image runs as its existing unprivileged postgres uid/gid.
        run("sudo", "-n", "chown", "999:999", *map(str, owned))
        runtime = {
            "applicationUser": "arkeniva_app", "applicationPassword": password,
            "database": "arkeniva_test", "port": 15432, "wrongSanPort": 15433,
        }
        private_file(directory / "runtime.json", json.dumps(runtime) + "\n")
        query = urlencode({"sslmode": "verify-full", "sslrootcert": str(directory / "ca.crt")})
        def endpoint(port):
            return f"postgres://arkeniva_app:{password}@127.0.0.1:{port}/arkeniva_test?{query}"
        environment = {
            "PG_FIXTURE_DIRECTORY": str(directory),
            "ARKENIVA_POSTGRES_IMAGE": "postgres:18.6-bookworm@sha256:6b38fe68f2c02cafffbbce7496f76d110d8a947c039bd22c067e9a43c2250240",
            "ARKENIVA_POSTGRES_CONTAINER_LIMITS": "memory=768MiB;cpus=1;pids=128;per-container",
            "ARKENIVA_POSTGRES_DISPOSABLE": "1",
            "ARKENIVA_POSTGRES_URL": endpoint(15432),
            "ARKENIVA_POSTGRES_WRONG_SAN_URL": endpoint(15433),
            "DATABASE_URL": endpoint(15432),
        }
        private_file(directory / "environment.json", json.dumps(environment) + "\n")
        if github_environment:
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
