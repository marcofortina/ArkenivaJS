# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Create an owned disposable OpenLDAP fixture inside the integration VM only."""
import base64
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

os.umask(0o077)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--github-env', type=Path)
args = parser.parse_args()
root = Path(tempfile.mkdtemp(prefix="arkenivajs-ldap-"))

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def password_hash(value):
    salt = secrets.token_bytes(16)
    return "{SSHA}" + base64.b64encode(hashlib.sha1(value.encode() + salt).digest() + salt).decode()

admin, service, user = (secrets.token_urlsafe(32) for _ in range(3))
run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2", "-subj", "/CN=Owned LDAP Fixture CA", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"))
for name, san in [("server", "DNS:localhost,IP:127.0.0.1"), ("wrong", "DNS:wrong.invalid")]:
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name, "-keyout", str(root / (name + ".key")), "-out", str(root / (name + ".csr")))
    (root / (name + ".ext")).write_text("subjectAltName=" + san + "\nextendedKeyUsage=serverAuth\n")
    run("openssl", "x509", "-req", "-in", str(root / (name + ".csr")), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "2", "-sha256", "-extfile", str(root / (name + ".ext")), "-out", str(root / (name + ".crt")))

base = "dc=fixture,dc=invalid"
records = [f"dn: {base}\nobjectClass: domain\ndc: fixture", f"dn: ou=people,{base}\nobjectClass: organizationalUnit\nou: people", f"dn: ou=groups,{base}\nobjectClass: organizationalUnit\nou: groups", f"dn: cn=service,{base}\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: service\nuserPassword: {password_hash(service)}"]
records.extend([f"dn: ou=referrals,{base}\nobjectClass: organizationalUnit\nou: referrals", f"dn: cn=outside,ou=referrals,{base}\nobjectClass: referral\nobjectClass: extensibleObject\ncn: outside\nref: ldap://127.0.0.1:19389/dc=outside,dc=invalid"])
for index, uid in enumerate(["alice", "bob", "duplicate", "duplicate", "étoile"] + ["employee-" + str(i) for i in range(16)]):
    encoded = base64.b64encode(uid.encode()).decode()
    records.append(f"dn: cn=person-{index},ou=people,{base}\nobjectClass: inetOrgPerson\ncn: person-{index}\nsn: Fixture\nuid:: {encoded}\nuserPassword: {password_hash(user)}")
for name, members in [("engineering", [f"cn=person-0,ou=people,{base}", f"cn=company,ou=groups,{base}"]), ("company", [f"cn=engineering,ou=groups,{base}"])]:
    records.append(f"dn: cn={name},ou=groups,{base}\nobjectClass: groupOfNames\ncn: {name}\n" + "\n".join("member: " + member for member in members))
(root / "seed.ldif").write_text("\n\n".join(records) + "\n")
config = f"""include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
modulepath /usr/lib/ldap
moduleload back_mdb
pidfile /tmp/slapd.pid
argsfile /tmp/slapd.args
TLSCACertificateFile /fixture/ca.crt
TLSCertificateFile /fixture/CERT.crt
TLSCertificateKeyFile /fixture/CERT.key
TLSProtocolMin 3.3
security simple_bind=128
database mdb
maxsize 16777216
suffix "{base}"
rootdn "cn=admin,{base}"
rootpw {password_hash(admin)}
directory /data
index objectClass eq
index uid eq
access to attrs=userPassword by anonymous auth by * none
access to * by dn.exact="cn=service,{base}" read by * none
"""
for name, port, plain_port in [("server", 16389, 13389), ("wrong", 16390, 13390)]:
    folder = root / name
    folder.mkdir()
    for filename in ["ca.crt", name + ".crt", name + ".key", "seed.ldif"]:
        (folder / filename).write_bytes((root / filename).read_bytes())
    (folder / "slapd.conf").write_text(config.replace("CERT", name))
    run("docker", "run", "--detach", "--name", "arkenivajs-ldap-" + root.name.removeprefix("arkenivajs-ldap-") + "-" + name, "--read-only", "--network", "bridge", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--tmpfs", "/data:rw,noexec,nosuid,size=32m", "--mount", "type=bind,source=" + str(folder) + ",target=/fixture,readonly", "--publish", "127.0.0.1:" + str(port) + ":1636", "--publish", "127.0.0.1:" + str(plain_port) + ":1389", "arkenivajs-owned-ldap:r1")
(root / "runtime.json").write_text(json.dumps({"directory": str(root), "bindDn": "cn=service," + base, "bindPassword": service, "userPassword": user, "baseDn": "ou=people," + base, "groupBaseDn": "ou=groups," + base, "ca": str(root / "ca.crt"), "caPem": (root / "ca.crt").read_text(), "containers": ["arkenivajs-ldap-" + root.name.removeprefix("arkenivajs-ldap-") + "-" + name for name in ["server", "wrong"]]}))
if args.github_env:
    with args.github_env.open('a') as output:
        output.write('ARKENIVA_LDAP_FIXTURE=' + str(root / 'runtime.json') + '\n')
print(root / "runtime.json")
