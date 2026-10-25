# Dependency inventory and SPDX evidence

Run the repository's exact pnpm version after a frozen install. No additional
SBOM generator is installed: this tool calls the pinned package manager's
[native SPDX 2.3 generator](https://pnpm.io/cli/sbom).

Choose a new absolute directory with an existing parent, outside every Git
checkout. The source checkout must be clean:

```sh
pnpm install --frozen-lockfile
node tools/security/supply-chain.mjs /private/new-supply-chain-evidence
pnpm test:supply-chain
```

The tool creates a private directory (0700) and private files (0600), refuses
existing destinations and paths inside Git, and checks source identity again
before completing. It never changes dependencies, source or package versions.
`--allow-dirty` supports local development checks and explicitly records
`dirty: true`; those results cannot identify a reproducible release commit.

## Retained files

- `inventory.json`: exact source commit, dirty status, Node/platform/architecture,
  pnpm version, each workspace manifest and its direct declared/locked dependency
  references, all lockfile package resolutions, platform constraints, input hashes
  and separately hashed local dependency patches.
- `*.full.spdx.json`: one native SBOM for each workspace project, including its
  development dependencies. The root, examples and development tools have their
  own documents.
- `*.runtime.spdx.json`: one production-dependency SBOM for each framework package.
- `licenses.json`: installed package names, versions and declared licenses,
  collected by `pnpm licenses list`; machine-local installation paths are omitted.
- `command-*.log`: private package-manager diagnostics.

The exact workspace importer list comes from the parsed multi-document pnpm
lockfile. Lockfile sections also retain package-manager distributions, including
platform variants; these locked entries are not a claim that every variant was
installed or tested on the current machine.

## Verification and scope

Each SBOM must identify the intended package/version/license, use unique local
component identifiers, reference existing components, include every locked direct
dependency with an actual dependency edge, and retain runtime dependency edges
for included workspace packages. An unknown declared license, missing dependency
or dangling reference fails the command. The semantic checks complement the
package manager's standard-format output; they are not a legal license analysis.

Separate project documents preserve the dependency edges that can be lost by
pnpm's merged workspace output. `inventory.json` lists the documents and their
component/relationship counts; it does not invent a merged SPDX document.

Upstream tarball checksums do not describe an applied local patch. For example,
the NATS SBOM retains its upstream tarball checksum while `inventory.json`
identifies the exact reviewed declaration patch and its SHA-256. Both belong in
the retained build evidence. Package archive hashes and contents require the
independent package checks.

Use the [package archive verifier](package-contents.md) to rebuild and retain
actual archive contents, export targets and per-file checksums from a clean
checkout. It complements these dependency inventories.

The evidence describes resolved JavaScript dependencies and known local patches.
Database servers, container images, operating-system packages, external tools
and optional native runtime libraries require their own reviewed inventories.
It does not authorize publication or replace vulnerability scanning, live
compatibility checks, public API review and the other release gates.

The `security` workflow runs the input/graph guards, creates this evidence from
the clean checked-out commit, runs the high/critical dependency audit gate and
retains the resulting artifacts for 14 days. It uses read-only repository
permissions and does not install an additional SBOM tool or publish packages.
