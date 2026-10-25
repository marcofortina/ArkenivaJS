# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Initiate dedicated TLS replica sets and scoped SCRAM users through container loopback."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def bootstrap(directory):
    environment_file = directory / "environment.json"
    credentials_file = directory / "bootstrap.json"
    if any(path.stat().st_mode & 0o077 for path in (environment_file, credentials_file)):
        raise ValueError("MongoDB fixture credentials must remain private")
    environment = json.loads(environment_file.read_text())
    if environment.get("ARKENIVA_MONGODB_DISPOSABLE") != "1":
        raise ValueError("Only an explicitly disposable MongoDB fixture may be initialized")
    credentials = json.loads(credentials_file.read_text())
    process_environment = os.environ.copy()
    process_environment.update(environment)
    compose = Path(__file__).with_name("compose.yaml")
    for service, host in (("mongodb", "localhost"), ("wrong-san", "wrong.invalid")):
        shell = ["docker", "compose", "-f", str(compose), "exec", "-T", service,
                 "mongosh", f"mongodb://{host}:27017/admin?directConnection=true&serverSelectionTimeoutMS=1000&connectTimeoutMS=1000",
                 "--quiet", "--norc", "--tls", "--tlsCAFile", "/fixture/ca.crt"]
        deadline = time.monotonic() + 90
        while True:
            # The shell must connect before its script can run; wait without retrying a partially applied bootstrap.
            try:
                probe = subprocess.run(shell + ["--eval", "if(db.adminCommand({ping:1}).ok!==1)quit(1);"],
                    env=process_environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
                if probe.returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("The disposable MongoDB TLS listener did not become ready")
            time.sleep(0.1)
        # No administrator credential is mounted into the server or placed in command arguments.
        script = "const credentials = " + json.dumps(credentials) + ";\n" + r"""
const admin = db.getSiblingDB('admin');
const deadline = Date.now() + 90000;
let ready = false;
while (!ready && Date.now() < deadline) {
  try { ready = admin.runCommand({ping:1}).ok === 1; } catch {}
  if (!ready) sleep(100);
}
if (!ready) throw new Error('MongoDB did not accept a local TLS connection');
const initiated = admin.runCommand({replSetInitiate:{_id:'arkeniva',members:[{_id:0,host:__HOST__+':27017'}]}});
if (initiated.ok !== 1) throw new Error('The disposable replica set could not be initiated');
while (!admin.runCommand({hello:1}).isWritablePrimary) {
  if (Date.now() >= deadline) throw new Error('The disposable replica set did not elect its primary');
  sleep(100);
}
admin.createUser({user:credentials.root.username,pwd:credentials.root.password,roles:[{role:'root',db:'admin'}],mechanisms:['SCRAM-SHA-256']});
if (!admin.auth(credentials.root.username,credentials.root.password)) throw new Error('The administrator could not authenticate');
db.getSiblingDB(credentials.database).createUser({user:credentials.app.username,pwd:credentials.app.password,roles:[{role:'readWrite',db:credentials.database}],mechanisms:['SCRAM-SHA-256']});
admin.createUser({user:credentials.probe.username,pwd:credentials.probe.password,roles:[{role:'read',db:'arkeniva_health'}],mechanisms:['SCRAM-SHA-256']});
print('Disposable TLS replica set, scoped application user and health identity are ready');
""".replace("__HOST__", json.dumps(host))
        subprocess.run(shell + ["--file", "/dev/stdin"], input=script, text=True,
            env=process_environment, check=True, timeout=120,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("Disposable MongoDB replica sets and scoped certificate-verified SCRAM users initialized")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    bootstrap(arguments.directory.resolve())
