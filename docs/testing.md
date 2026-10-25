# Test results and machine-readable reports

Run `pnpm verify` from a frozen, built workspace on a supported Node runtime.
It checks formatting, lint, build, strict types, test tooling, unit/contracts,
coverage, executable guides, documentation and ESM smoke. Real disposable
backend suites remain additional mandatory checks for affected adapters; Oracle
live compatibility is explicitly optional and cannot be inferred from mocks.

`pnpm test:tooling` checks the actual native reporter output, including passing
and failing suites, coverage extraction and unsafe destination rejection. It
does not require a database or production credentials.

Set `ARKENIVA_TEST_REPORT_DIRECTORY` to enable native Node JUnit output while
retaining readable standard output and the test process's actual exit status:

```sh
ARKENIVA_TEST_REPORT_DIRECTORY=/private/test-reports pnpm test:unit
ARKENIVA_TEST_REPORT_DIRECTORY=/private/test-reports pnpm test:contract
ARKENIVA_TEST_REPORT_DIRECTORY=/private/test-reports pnpm coverage
```

The shared workspace runner emits `workspace-unit.junit.xml`,
`workspace-contract.junit.xml`, `workspace-all-coverage.junit.xml` and
`workspace-all-coverage.lcov`. Package-scoped invocations include their package
path in the label. Coverage uses the same includes and thresholds as the
ordinary command. Reports never select tests, suppress failures, replace real
integration infrastructure or turn skipped checks into passes. Existing regular
report files can be refreshed; symlink destinations and unsafe labels fail.

The runner creates report directories and destination files with owner-only
access. Use disposable external output locations,
retain reports according to the CI retention policy, and never commit raw
quality artifacts or secrets. Without the variable, the existing ordinary
reporter behavior and file selection remain unchanged.
