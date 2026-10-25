import assert from 'node:assert/strict';
import { mkdirSync, realpathSync, lstatSync, openSync, closeSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';

/** Add native machine-readable reporters without changing test selection or failure status. */
export function testReportArguments(
  label,
  coverage,
  directory = process.env.ARKENIVA_TEST_REPORT_DIRECTORY,
) {
  if (directory === undefined) return [];
  assert.match(label, /^[a-z0-9][a-z0-9-]{0,127}$/);
  assert.ok(
    typeof directory === 'string' && directory.length > 0,
    'A test report directory is required',
  );
  const target = resolve(directory);
  mkdirSync(target, { recursive: true, mode: 0o700 });
  assert.ok(!lstatSync(target).isSymbolicLink(), 'The report directory must not be a symlink');
  const canonical = realpathSync(target);
  const filename = (extension) => {
    const path = join(canonical, label + extension);
    try {
      assert.ok(
        lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink(),
        'A report destination must be a regular file',
      );
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      closeSync(openSync(path, 'wx', 0o600));
    }
    chmodSync(path, 0o600);
    return path;
  };
  return [
    '--test-reporter=spec',
    '--test-reporter-destination=stdout',
    '--test-reporter=junit',
    '--test-reporter-destination=' + filename('.junit.xml'),
    ...(coverage
      ? ['--test-reporter=lcov', '--test-reporter-destination=' + filename('.lcov')]
      : []),
  ];
}
