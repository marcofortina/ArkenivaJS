# Isolated secret-history and current-tree scanning

The [dependency inventory and SPDX guide](supply-chain.md) describes the separate
supply-chain job and its private reproducible artifacts. Secret scanning remains
an independent required check.

Run `run.py` only inside a disposable VM or CI runner with Docker available.
The source repository must be clean and non-shallow; partial history or
uncommitted input is rejected. The output directory must be new, outside Git,
and have an existing parent.

```sh
ARKENIVA_SECURITY_DISPOSABLE=1 python3 tools/security/run.py /path/to/source /private/secret-scan
```

The tool uses upstream Gitleaks 8.30.1, pinned to its official container digest.
It scans all reachable history and separately scans the complete current directory,
mounts source read-only, disables container
networking, drops Linux capabilities, applies CPU/memory/process limits, and
runs with the invoking user's UID/GID. Docker is never installed by the script.
Credentials are redacted in scanner output and reports. Inline suppression
comments are ignored; unreviewed findings cannot be converted into success by the wrapper.

The owner-approved [public-vector review](reviewed-public-vectors.json) identifies
exactly one immutable commit/file/rule/line fingerprint for the published
[RFC 6238 Appendix B SHA1 test seed](https://www.rfc-editor.org/rfc/rfc6238.html#appendix-B).
The source-root [`.gitleaksignore`](../../.gitleaksignore) contains that single
commit-qualified fingerprint. The tool verifies both tracked policy files,
historical source-line SHA-256 and decoded public fixture before using the root
ignore for the history scan. A changed
fingerprint, rule, source line or standard fails validation. No source path or
scanner rule is excluded. The summary records the reviewed fingerprint separately
from remaining findings. History stays intact, and every other finding still
fails the gate. The separate current-directory scan always uses an explicit empty
ignore file: the historical approval never suppresses a current-tree finding.
Toy repositories without this review also use an explicit empty history ignore;
implicit repository ignore discovery cannot broaden the exception. Custom
repository rule configuration is rejected so the pinned upstream rules remain active.

`findings.json`, `scanner.log`, `tree-findings.json`, `tree-scanner.log` and
`summary.json` remain in a private external
directory. The summary identifies exact source SHA, scanner/image, commit count,
result and coverage limits without printing discovered credential values.
Any finding, missing report, tool failure or deadline failure is a failed check.
Review a finding without copying its secret into a public issue or log. A
pattern scan complements authentication, dependency audits, secure fixtures and
repository protections; it cannot prove every possible secret is absent.

Gitleaks is an external MIT-licensed development tool and is not shipped in
framework packages. Upstream has declared the feature set complete and future
maintenance focused on security patches; review its status when updating pins.
Sources: [official project](https://github.com/gitleaks/gitleaks) and
[pinned release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).

Verify the scanner wrapper on the same disposable runner:

```sh
ARKENIVA_SECURITY_DISPOSABLE=1 python3 tools/security/test.py
```

The tests use private temporary repositories. A clean repository passes; a
synthetic credential committed and then deleted still fails the history scan,
with redaction verified. Dirty and shallow input is rejected. The synthetic
pattern has no provider account or external validity and never enters product
Git history.

Additional negative checks clone the clean product history, verify the public
fixture review, then add a separate synthetic credential that must still fail
with redaction. They reintroduce the public fixture at the same pathname and line
in a different commit: both history and current-tree scans must report it.
An ignored local synthetic credential must fail the directory scan even when
history is clean. Missing or broadened root ignores, modified review fingerprints
and custom rule configuration fail before scanning.

The security workflow checks a complete checkout on main pushes, weekly runs
and explicit dispatch. It runs these negative tests before scanning product
history and retains redacted evidence for 14 days. A failed scanner or missing
report remains a failed job.
