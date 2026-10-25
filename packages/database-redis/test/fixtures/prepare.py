"""Create private Redis TLS certificates, scoped ACL accounts and disposable data directories."""

import argparse
import hashlib
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
            raise ValueError("Redis fixture credentials must stay outside a Git checkout")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous_mask = os.umask(0o077)
    try:
        passwords = {role: secrets.token_hex(32) for role in ("app", "probe", "control")}
        prefix = "arkeniva_test_" + secrets.token_hex(12) + ":"
        permissions = {
            "app": "~" + prefix + "* &" + prefix + "* +ping +get +strlen +pttl +set +del +incrby +eval +eval_ro +publish +subscribe +unsubscribe +select +client|id +hset +hgetall +multi +exec +discard +watch +unwatch",
            "probe": "+ping",
            "control": "+ping +info +client|kill +client|pause +client|unpause",
        }
        acl = "user default reset off\n"
        for role, password in passwords.items():
            digest = hashlib.sha256(password.encode()).hexdigest()
            acl += "user arkeniva_" + role + " reset on #" + digest + " " + permissions[role] + "\n"
        private_file(directory / "users.acl", acl)
        private_file(directory / "health-password", passwords["probe"] + "\n")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=ArkenivaJS disposable Redis CA",
            "-keyout", str(directory / "ca.key"), "-out", str(directory / "ca.crt"))
        # The caller and the container uid retain separate readable copies of the public CA.
        private_file(directory / "server-ca.crt", (directory / "ca.crt").read_text(encoding="utf-8"))
        for name, identities in (("server", "DNS:localhost,IP:127.0.0.1"), ("wrong-san", "DNS:wrong.invalid")):
            private_file(directory / (name + ".ext"), "subjectAltName=" + identities + "\nextendedKeyUsage=serverAuth\n")
            run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
                "-keyout", str(directory / (name + ".key")), "-out", str(directory / (name + ".csr")))
            run("openssl", "x509", "-req", "-days", "3", "-in", str(directory / (name + ".csr")),
                "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"),
                "-set_serial", str(secrets.randbits(128)), "-extfile", str(directory / (name + ".ext")),
                "-out", str(directory / (name + ".crt")))
        private_file(directory / "redis.conf", "\n".join((
            "bind 0.0.0.0", "protected-mode yes", "port 0", "tls-port 6379",
            "tls-cert-file /fixture/server.crt", "tls-key-file /fixture/server.key",
            "tls-ca-cert-file /fixture/ca.crt", "tls-auth-clients no",
            'tls-protocols "TLSv1.2 TLSv1.3"', "aclfile /fixture/users.acl",
            "acllog-max-len 0", "databases 1", "dir /data", "daemonize no", 'logfile ""',
            'save ""', "appendonly yes", "appendfsync always", "maxmemory 96mb",
            "maxmemory-policy noeviction", "maxclients 128", "\n",
        )))
        private_file(directory / "healthcheck.sh", "\n".join((
            "#!/bin/sh", "set -eu",
            'REDISCLI_AUTH=$(cat /fixture/health-password)', "export REDISCLI_AUTH",
            'exec redis-cli --tls --cacert /fixture/ca.crt --sni "${REDIS_HEALTH_SERVER_NAME:-localhost}" --user arkeniva_probe -h 127.0.0.1 -p 6379 ping', "",
        )))
        owned = [directory / name for name in (
            "server.key", "server.crt", "wrong-san.key", "wrong-san.crt", "server-ca.crt",
            "users.acl", "health-password", "healthcheck.sh", "redis.conf",
        )]
        for name in ("data-server", "data-wrong-san"):
            path = directory / name
            path.mkdir(mode=0o700)
            owned.append(path)
        run("sudo", "-n", "chown", "999:999", *map(str, owned))

        def endpoint(port, role="app"):
            query = urlencode({"sslca": str(directory / "ca.crt"), "prefix": prefix})
            return f"rediss://arkeniva_{role}:{passwords[role]}@localhost:{port}/0?{query}"

        environment = {
            "REDIS_FIXTURE_DIRECTORY": str(directory),
            "ARKENIVA_REDIS_IMAGE": "redis:8.10.2@sha256:97ec88159e6d7cfb5ddef9015386087d58a912de80112f06ebdfa78fa5989901",
            "ARKENIVA_REDIS_DISPOSABLE": "1",
            "ARKENIVA_REDIS_URL": endpoint(16379),
            "ARKENIVA_REDIS_WRONG_SAN_URL": endpoint(16380),
            "ARKENIVA_REDIS_CONTROL_URL": endpoint(16379, "control"),
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
