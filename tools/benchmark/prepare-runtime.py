# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Install integrity-pinned benchmark tools into a new private directory outside Git."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

TOOLS = (
    ("node-v24.22.1-linux-x64.tar.xz",
     "https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz",
     "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6"),
    ("k6-v2.3.0-linux-amd64.tar.gz",
     "https://github.com/grafana/k6/releases/download/v2.3.0/k6-v2.3.0-linux-amd64.tar.gz",
     "39c3117b6af817592dcd0ce4242105c0a7af10948c2a425306f0be8f7a8a8ab1"),
)


def prepare(directory):
    directory = directory.absolute()
    for parent in (directory, *directory.parents):
        if parent.is_symlink() or (parent / ".git").exists():
            raise ValueError("Benchmark tools require an external directory without symlink parents")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    previous = os.umask(0o077)
    try:
        archives = []
        for name, url, expected in TOOLS:
            path = directory / name
            digest = hashlib.sha256()
            size = 0
            with urllib.request.urlopen(url, timeout=60) as response, path.open("xb") as output:
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > 150 * 1024 * 1024:
                        raise ValueError("The benchmark archive exceeds its download bound")
                    digest.update(block)
                    output.write(block)
            if digest.hexdigest() != expected:
                raise ValueError("The benchmark tool archive failed SHA-256 verification")
            with tarfile.open(path) as archive:
                members = archive.getmembers()
                if len(members) > 20000 or sum(member.size for member in members) > 1024**3:
                    raise ValueError("The benchmark archive exceeds its extraction bounds")
                archive.extractall(directory, filter="data")
            archives.append({"file": name, "url": url, "sha256": expected, "bytes": size})
        node = directory / "node-v24.22.1-linux-x64/bin/node"
        k6 = directory / "k6-v2.3.0-linux-amd64/k6"
        node_version = subprocess.check_output([node, "--version"], text=True).strip()
        k6_version = subprocess.check_output([k6, "version"], text=True).strip()
        if node_version != "v24.22.1" or not k6_version.startswith("k6 v2.3.0"):
            raise ValueError("The installed benchmark tool has an unexpected version")
        environment = os.environ.copy()
        environment["PATH"] = str(node.parent) + os.pathsep + environment.get("PATH", "")
        npm = node.parent.parent / "lib/node_modules/npm/bin/npm-cli.js"
        subprocess.run([node, npm, "install", "--prefix", directory / "corepack", "--ignore-scripts",
                        "--no-fund", "corepack@0.36.0"], env=environment, cwd=directory, check=True)
        corepack = directory / "corepack/node_modules/corepack/dist/corepack.js"
        if subprocess.check_output([node, corepack, "--version"], env=environment, text=True).strip() != "0.36.0":
            raise ValueError("Unexpected Corepack version")
        manifest = {"node": str(node), "k6": str(k6), "corepack": str(corepack),
                    "nodeVersion": node_version, "k6Version": k6_version, "archives": archives,
                    "license": {"node": "MIT with bundled dependency notices", "k6": "AGPL-3.0; external development tool only", "corepack": "MIT"}}
        (directory / "tools.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"nodeVersion": node_version, "k6Version": k6_version, "archivesVerified": len(archives)}))
    finally:
        os.umask(previous)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    prepare(parser.parse_args().directory)
