# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Seed the native Kafka installer's source cache from identical verified bytes."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit


VERSION = "1.3.2"
ARCHIVE_URL = (
    "https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz"
)
ARCHIVE_BYTES = 1502830
ARCHIVE_SHA256 = "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"
VENDOR_GUARDS = {
    "util/configure.js":
        "3d6fc1a5024a08c5736f2b18da6a68dfef13732c0bc72a9f0ecf25a51225e508",
    "deps/librdkafka/mklove/modules/configure.zlib":
        "769d70e192903aa3b720fd45387eb7fc35ff6469cca9eec8f795299179aea28c",
}


def approved_origin(url):
    destination = urlsplit(url)
    if (destination.scheme != "https" or destination.username or destination.password
            or destination.port not in (None, 443) or destination.hostname not in {
                "github.com", "release-assets.githubusercontent.com",
                "objects.githubusercontent.com",
            }):
        raise ValueError("The native source redirect is not an approved HTTPS origin")


class ApprovedRedirects(urllib.request.HTTPRedirectHandler):
    """Check every redirect before urllib can contact the next origin."""

    def redirect_request(self, request, response, code, message, headers, destination):
        approved_origin(destination)
        return super().redirect_request(
            request, response, code, message, headers, destination,
        )


def owned_directory(path):
    """Refuse links, other owners and directories writable by another identity."""
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022):
        raise ValueError("A native source directory is not exclusively owned")
    return info.st_dev, info.st_ino


def owned_chain(root, path):
    relative = path.relative_to(root)
    owned_directory(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            owned_directory(current)
        else:
            break


def cache_target(workspace):
    """Resolve the declared workspace dependency, never an external shared cache."""
    workspace = workspace.absolute()
    if workspace.resolve() != workspace:
        raise ValueError("The workspace must be a real normalized directory")
    owned_directory(workspace)
    cache = workspace / "node_modules/.pnpm"
    owned_chain(workspace, cache)
    sdk = (workspace / "packages/messaging-kafka/node_modules/"
           "@confluentinc/kafka-javascript").resolve(strict=True)
    sdk.relative_to(cache)
    owned_chain(workspace, sdk)
    manifest = json.loads((sdk / "package.json").read_text())
    if (manifest.get("name") != "@confluentinc/kafka-javascript"
            or manifest.get("version") != "1.11.0"):
        raise ValueError("The native Kafka SDK identity is not the pinned version")
    target = sdk / "deps/librdkafka/mklove/deps/src/zlib"
    owned_chain(sdk, target.parent)
    if target.exists() or target.is_symlink():
        raise ValueError("The native zlib source cache must be absent")
    return sdk, target


def guard_vendor(sdk):
    for relative, expected in VENDOR_GUARDS.items():
        path = sdk / relative
        owned_chain(sdk, path.parent)
        if (path.is_symlink() or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise ValueError("The reviewed native source installer has changed")


def verified_archive(data):
    if (len(data) != ARCHIVE_BYTES
            or hashlib.sha256(data).hexdigest() != ARCHIVE_SHA256):
        raise ValueError("The native zlib archive failed its pinned checksum")
    return data


def download_archive():
    started = time.monotonic()
    request = urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": "ArkenivaJS-CI"})
    approved_origin(request.full_url)
    opener = urllib.request.build_opener(ApprovedRedirects())
    with opener.open(request, timeout=15) as response:
        approved_origin(response.url)
        chunks = []
        count = 0
        while count <= ARCHIVE_BYTES:
            if time.monotonic() - started > 60:
                raise TimeoutError("The native source download deadline expired")
            chunk = response.read(min(65536, ARCHIVE_BYTES + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
    return verified_archive(b"".join(chunks))


def extract_archive(data, directory):
    """Validate every entry before writing only bounded regular files/directories."""
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 512 or sum(item.size for item in members) > 8 * 1024 * 1024:
            raise ValueError("The native source archive exceeds its extraction budget")
        seen = set()
        for item in members:
            path = PurePosixPath(item.name)
            if (not path.parts or path.is_absolute() or ".." in path.parts
                    or "\\" in item.name or len(item.name) > 1024
                    or path.parts[0] != "zlib-" + VERSION
                    or path in seen or not (item.isfile() or item.isdir())
                    or item.size < 0):
                raise ValueError("The native source archive contains an unsafe entry")
            seen.add(path)
        for item in members:
            path = directory / item.name
            if item.isdir():
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with path.open("xb") as output:
                    shutil.copyfileobj(archive.extractfile(item), output)
                path.chmod(item.mode & 0o755)
    return directory / ("zlib-" + VERSION)


def publish_cache(source, target):
    """Reserve a fresh target exclusively; never replace an existing cache."""
    missing = []
    current = target.parent
    while not current.exists():
        if current.is_symlink():
            raise ValueError("The native cache parent cannot be a link")
        missing.append(current)
        current = current.parent
    owned_directory(current)
    for current in reversed(missing):
        current.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    identity = owned_directory(target)
    try:
        if any(path.is_symlink() for path in source.rglob("*")):
            raise ValueError("The configured native source cannot contain links")
        for child in source.iterdir():
            if owned_directory(target) != identity:
                raise ValueError("The owned native source cache identity changed")
            destination = target / child.name
            if child.is_dir():
                shutil.copytree(child, destination)
            else:
                with child.open("rb") as input_file, destination.open("xb") as output:
                    shutil.copyfileobj(input_file, output)
                destination.chmod(child.stat().st_mode & 0o755)
    except BaseException:
        if target.exists() and owned_directory(target) == identity:
            shutil.rmtree(target)
        raise


def seed(workspace, reports):
    sdk, target = cache_target(workspace)
    guard_vendor(sdk)
    reports = reports.absolute()
    if reports.resolve() != reports or reports.is_relative_to(workspace.absolute()):
        raise ValueError("Native source reports require a real external directory")
    owned_directory(reports)
    data = download_archive()
    with tempfile.TemporaryDirectory(prefix="kafka-zlib-source-", dir=reports) as staging:
        source = extract_archive(data, Path(staging))
        configure = source / "configure"
        if configure.is_symlink() or not configure.is_file():
            raise ValueError("The verified native source configure script is missing")
        with (reports / "zlib-source-configure.log").open("xb") as output:
            subprocess.run(
                [str(configure), "--static", "--prefix=/usr"], cwd=source,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                     "CFLAGS": "-fPIC", "libdir": "/usr/lib"},
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                timeout=60, check=True,
            )
        if not (source / "Makefile").is_file():
            raise ValueError("Verified zlib configuration did not create its source cache")
        owned_chain(sdk, target.parent)
        publish_cache(source, target)
    result = {"status": "PASS", "archiveUrl": ARCHIVE_URL,
              "archiveBytes": len(data), "archiveSha256": ARCHIVE_SHA256,
              "vendorGuards": VENDOR_GUARDS, "sourceCache": str(target),
              "staticLinkageUnchanged": True, "nativeRebuildPerformed": False}
    with (reports / "zlib-source-seed.json").open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    return result


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("reports", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(seed(arguments.workspace, arguments.reports)))
