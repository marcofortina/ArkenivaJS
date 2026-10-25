import { readdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
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
const result = spawnSync(process.execPath, ['--test', ...flags, ...files], { stdio: 'inherit' });
process.exitCode = result.status ?? 1;
