"""Create private, disposable MariaDB accounts and TLS material outside any checkout."""

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
            raise ValueError("MariaDB fixture credentials must stay outside a Git checkout")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous_mask = os.umask(0o077)
    try:
        password = secrets.token_hex(32)
        private_file(directory / "admin-password", secrets.token_hex(32) + "\n")
        private_file(directory / "init.sql", (
            "CREATE USER 'arkeniva_app'@'%' IDENTIFIED BY '" + password + "' REQUIRE SSL;\n"
            "GRANT ALL PRIVILEGES ON arkeniva_test.* TO 'arkeniva_app'@'%';\n"
        ))
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=ArkenivaJS disposable MariaDB CA",
            "-keyout", str(directory / "ca.key"), "-out", str(directory / "ca.crt"))
        # Separate public CA copies let both the invoking client user and MariaDB uid read their own files.
        private_file(directory / "server-ca.crt", (directory / "ca.crt").read_text(encoding="utf-8"))
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
            "server.key", "server.crt", "wrong-san.key", "wrong-san.crt", "server-ca.crt",
            "admin-password", "init.sql",
        )]
        for name in ("data-server", "data-wrong-san"):
            path = directory / name
            path.mkdir(mode=0o700)
            owned.append(path)
        # The pinned image's existing mysql user owns private files and data directories.
        run("sudo", "-n", "chown", "999:999", *map(str, owned))
        def endpoint(port):
            query = urlencode({"ssl": "verify-full", "sslca": str(directory / "ca.crt")})
            return f"mariadb://arkeniva_app:{password}@localhost:{port}/arkeniva_test?{query}"
        environment = {
            "MARIADB_FIXTURE_DIRECTORY": str(directory),
            "ARKENIVA_MARIADB_IMAGE": "mariadb:12.3.3-noble@sha256:99c125f103f5d081ebbc9ffe064e63daf7f688ac33a5f7f29af2d7260a96debf",
            "ARKENIVA_MARIADB_DISPOSABLE": "1",
            "ARKENIVA_MARIADB_URL": endpoint(13307),
            "ARKENIVA_MARIADB_WRONG_SAN_URL": endpoint(13309),
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
