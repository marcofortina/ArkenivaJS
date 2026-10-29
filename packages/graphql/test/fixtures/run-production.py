# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Run real production-policy checks only on an explicitly disposable Linux network."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def run():
    if os.environ.get("ARKENIVA_GRAPHQL_DISPOSABLE_NETWORK") != "1":
        raise RuntimeError("Production fixtures require an explicitly disposable VM or CI runner")
    if os.environ.get("ARKENIVA_NATS_DISPOSABLE") != "1":
        raise RuntimeError("Production fixtures require the authenticated disposable NATS broker")
    node = shutil.which("node")
    if not node:
        raise RuntimeError("The selected supported Node runtime is unavailable")
    package = Path(__file__).resolve().parents[2]
    address = "11.0.0.1"

    def present():
        interfaces = json.loads(subprocess.check_output(["ip", "-json", "address", "show"], text=True))
        return any(info.get("local") == address for interface in interfaces for info in interface.get("addr_info", []))

    if present():
        raise RuntimeError("The isolated authority fixture address is already assigned")
    previous_mask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="arkeniva-graphql-production-") as temporary:
            directory = Path(temporary)
            certificate, key = directory / "authority.crt", directory / "authority.key"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=ArkenivaJS isolated production authority",
                "-addext", "subjectAltName=IP:" + address,
                "-keyout", str(key), "-out", str(certificate),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            environment = dict(os.environ, **{
                "ARKENIVA_GRAPHQL_PRODUCTION_FIXTURE": "1",
                "ARKENIVA_GRAPHQL_AUTHORITY_HOST": address,
                "ARKENIVA_GRAPHQL_AUTHORITY_CERT": str(certificate),
                "ARKENIVA_GRAPHQL_AUTHORITY_KEY": str(key),
                "NODE_EXTRA_CA_CERTS": str(certificate),
            })
            # The address exists only on this disposable machine. No DNS or TLS-policy override is used.
            subprocess.run(["sudo", "-n", "ip", "addr", "add", address + "/32", "dev", "lo"], check=True)
            try:
                tests = sorted((package / "dist-test/integration").glob("nats*.integration.test.js"))
                tests.append(package / "dist-test/integration/production-subscription.integration.test.js")
                result = subprocess.run([node, "--test", "--test-reporter=spec", *map(str, tests)], cwd=package, env=environment, timeout=180)
            finally:
                subprocess.run(["sudo", "-n", "ip", "addr", "del", address + "/32", "dev", "lo"], check=True)
                if present():
                    raise RuntimeError("The isolated authority fixture address was not removed")
            return result.returncode
    finally:
        os.umask(previous_mask)


if __name__ == "__main__":
    raise SystemExit(run())
