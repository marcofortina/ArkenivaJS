# Private benchmark tool installation

Run `prepare-runtime.py` inside a disposable Linux x64 VM with Python 3.12 or
later. Choose a new directory outside any Git checkout; its parent must already
exist. Existing targets and symlink parents are rejected. The installer changes
no system packages and does not install a database or container engine.

```sh
python3 tools/benchmark/prepare-runtime.py /private/benchmark-tools
```

The exact tool inputs are Node 24.22.1, k6 2.3.0 and Corepack 0.36.0. Node and
k6 archives come from their official release locations and must match the
SHA-256 values embedded in the installer before extraction. Downloads are
bounded to 150 MiB each; extraction is bounded to 20,000 entries and 1 GiB of
declared content and uses Python's data extraction filter. Corepack is installed
within the private directory with package lifecycle scripts disabled. Exact
versions are checked after installation. `tools.json` records actual executable
paths, versions and archive identities; installation failures remain explicit.

```sh
export PATH="/private/benchmark-tools/node-v24.22.1-linux-x64/bin:/private/benchmark-tools/corepack/node_modules/.bin:$PATH"
node --version
pnpm --version
/private/benchmark-tools/k6-v2.3.0-linux-amd64/k6 version
```

Node uses MIT with bundled dependency notices; Corepack uses MIT. k6 is an
external AGPL-3.0 development executable, never a framework runtime dependency
or npm package payload. Preserve upstream licenses with the private tool files.
No binary, downloaded archive or installation output belongs in product Git.

Pins require a new upstream security/engine/license review before updating.
Sources: [Node releases](https://nodejs.org/dist/v24.22.1/),
[k6 release](https://github.com/grafana/k6/releases/tag/v2.3.0), and
[Corepack](https://github.com/nodejs/corepack).
