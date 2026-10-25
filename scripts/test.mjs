import { readdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { testReportArguments } from './test-reports.mjs';
const root = fileURLToPath(new URL('../', import.meta.url));
const invocation = relative(root, process.cwd()).split(sep).join('/');
const packagePrefix = /^packages\/[^/]+$/.test(invocation) ? `${invocation}/` : undefined;
if (invocation !== '' && !packagePrefix)
  throw new Error('The test runner requires the workspace root or a package directory');
// Resolve build outputs from the workspace while retaining an explicit package invocation's scope.
process.chdir(root);
const kind = process.argv[2] ?? 'all';
const coverage = process.argv.includes('--coverage');
function walk(path) {
  if (!existsSync(path)) return [];
  return readdirSync(path, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(`${path}/${e.name}`) : [`${path}/${e.name}`],
  );
}
const files = [...walk('.build/test'), ...walk('packages').filter((p) => p.includes('/dist-test/'))]
  .filter((p) => {
    if (packagePrefix && !p.startsWith(packagePrefix)) return false;
    if (!p.endsWith('.test.js')) return false;
    if (kind === 'all')
      return ['unit', 'contract', 'property'].some((suite) => p.endsWith(`.${suite}.test.js`));
    if (kind.endsWith('-integration'))
      return p.startsWith(`packages/${kind.slice(0, -12)}/`) && p.endsWith('.integration.test.js');
    if (kind === 'integration' && p.startsWith('packages/database-oracle/')) return false;
    return p.endsWith(`.${kind}.test.js`);
  })
  .sort();
if (files.length === 0) throw new Error(`No tests for ${kind}`);
const flags = coverage
  ? [
      '--experimental-test-coverage',
      '--test-coverage-include=packages/*/dist/*.js',
      '--test-coverage-lines=85',
      '--test-coverage-branches=85',
    ]
  : [];
const label = ((packagePrefix ?? 'workspace-') + kind + (coverage ? '-coverage' : '')).replaceAll(
  '/',
  '-',
);
const reporting = testReportArguments(label, coverage);
const result = spawnSync(process.execPath, ['--test', ...flags, ...reporting, ...files], {
  stdio: 'inherit',
});
process.exitCode = result.status ?? 1;
