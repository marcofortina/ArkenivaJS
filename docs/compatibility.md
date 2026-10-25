# Compatibility evidence

Use Node.js **22.23.4**, **24.22.1** or **26.12.1** with the exact package manager
in the root manifest. Node 24 is the primary development baseline. Exact pins
describe the tested development baseline; they do not guarantee every later
runtime or dependency release.

Linux x86-64 has actual local unit, contract, property, package-consumer and live
service evidence. The database package READMEs record the exact driver, server,
runtime, platform and last live verification date. Oracle has mandatory mock and
offline SDK contracts; **live Oracle compatibility is not verified**.

## Additional architecture checks

The manual and weekly `compatibility` workflow is configured for native Linux
x64 and arm64 runners on all three supported Node versions. It checks the
actual runtime architecture before building, runs the full service-independent
verification suite, executes examples against packed artifacts, and retains
runtime versions, JUnit and LCOV evidence for 14 days. Both architectures have
the same required checks; a failed matrix entry blocks the corresponding
release claim.

The configured runner labels are documented in the
[GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
The arm64 label requires a public repository. The workflow runs only on `main`
and does not publish packages.

A workflow definition is not execution evidence. **Linux arm64 remains
unverified until an actual successful run on the intended commit is retained.**
Service-independent adapter contracts do not establish live database or broker
compatibility on another architecture. Native addons require a separate actual
install/build/run and live-service gate for each claimed target.

Windows and macOS compatibility is not currently claimed. Driver and kernel
transport behavior must be tested on each platform before broadening that
statement; Unix-domain socket support is a POSIX/Linux guarantee only.

## Before a release

Run the compatibility workflow for the exact intended `main` commit, inspect
every matrix entry and retain its runtime and test artifacts. Also require the
normal mandatory CI jobs, the applicable live-service matrix and performance
gates. A skipped, unrun or failed check must remain visible in release evidence.
