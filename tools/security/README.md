# Isolated secret-history scanning

Run `run.py` only inside a disposable VM or CI runner with Docker available.
The source repository must be clean and non-shallow; partial history or
uncommitted input is rejected. The output directory must be new, outside Git,
and have an existing parent.

```sh
ARKENIVA_SECURITY_DISPOSABLE=1 python3 tools/security/run.py /path/to/source /private/secret-scan
```

The tool uses upstream Gitleaks 8.30.1, pinned to its official container digest.
It scans all reachable history, mounts source read-only, disables container
networking, drops Linux capabilities, applies CPU/memory/process limits, and
runs with the invoking user's UID/GID. Docker is never installed by the script.
Credentials are redacted in scanner output and reports. Inline suppression
comments are ignored; findings cannot be converted into success by the wrapper.

`findings.json`, `scanner.log` and `summary.json` remain in a private external
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
