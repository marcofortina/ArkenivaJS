# Private package archive verification

After a frozen install, use the workspace's exact pnpm version on a supported
Node runtime. Python 3, Git and the existing build tools are required; no
additional Python packages are installed.

```sh
pnpm test:package-contents
python3 -B tools/security/package_contents.py /private/new-package-evidence
```

Choose a fresh absolute destination whose parent exists outside every Git
checkout. The source checkout must be clean. The command rebuilds the entire
workspace, packs each framework package with pnpm, and inspects the actual
tar archives without extracting their contents. It rejects prepack, prepare and
postpack hooks; a future hook needs a separately reviewed update to the verifier.
Current package manifests contain no such hooks.

The evidence directory is private (0700), and archives, command logs and
`packages.json` have owner-only permissions (0600). Existing destinations are
rejected. No dependency installation, package publication, version changes or
Git operations that modify history are performed.

## Content checks

The verifier checks the reviewed file allowlist, required README/changelog/legal
notices, exact root LICENSE bytes, lockstep package versions, ESM/type export
targets, private package state and resolved workspace dependency references.
Packed file bytes must match the fresh build and maintained documentation.
Compiled files without a corresponding owned TypeScript source fail, catching
stale output left after source removal. Duplicate entries, links, traversal,
hidden configuration, tests, raw source directories and private keys fail.
Archive inspection has compressed/expanded byte and file-count ceilings.

The report identifies the exact clean source commit and package manager,
each archive's SHA-256 and each contained file's size/hash. Declaration hashes
support review of the public API against a prior candidate. They do not prove
semantic API compatibility; review signature/default/error changes separately.
Source identity and cleanliness are checked again before the final report.
Inspect full private command logs if a command fails; incomplete output is not
a successful verification report.

## Release scope

All package manifests stay private until publication is separately authorized.
These checks verify package contents; they do not authorize npm publication or
replace packed-consumer tests, vulnerability and complete-history secret scans,
dependency license review, native platform/live-service checks, benchmark and
soak gates, mandatory remote CI, publisher identity or scope ownership checks.
Keep unrun gates explicitly pending.

The security workflow runs the rejection fixtures and rebuilds/inspects archives
from its clean checkout on Node 24. It retains archives, full command logs and
the per-file report for 14 days using the pinned artifact action. This job has
read-only repository permissions and performs no publication. A workflow
definition becomes execution evidence only after the actual run succeeds.
