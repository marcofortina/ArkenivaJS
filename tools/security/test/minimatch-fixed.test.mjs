// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const require = createRequire(import.meta.url),
  consumer = createRequire(require.resolve('eslint/package.json')),
  manifest = consumer.resolve('minimatch/package.json'),
  installed = dirname(manifest);
// Exact unmodified npm release artifacts; the lockfile retains official integrity.
const officialHashes = {
  'LICENSE.md': '2c7c5d22ed5a8ee968c64757710979afcd77438c48b4a265b94e615babd8a901',
  'README.md': 'beadc58d3a39a2c3d208cfd5ff314adee2015d78fdafebbf11bc9c78b520c3de',
  'dist/commonjs/assert-valid-pattern.d.ts':
    'ff8872a24ed233ed9b80a521c1c5214ee996f4d649f537a1e8d12196d9f83d77',
  'dist/commonjs/assert-valid-pattern.d.ts.map':
    '6bda19e78c29faff99d261fb630e1b28ae01f61dd429861535834ae4fdbb9d59',
  'dist/commonjs/assert-valid-pattern.js':
    'fcd3b0e6efee67b11249804cc64bf4d22c883395491f79bfb484869d61823600',
  'dist/commonjs/assert-valid-pattern.js.map':
    '93d366c74b6028b0b32b257a681cb52d6b1243113916fdd6c2a67daf597d69e3',
  'dist/commonjs/escape.d.ts': 'a7224113134dbd16bcf5e95e31b02f2d3da83aa99756a4b3cd133031670c72fc',
  'dist/commonjs/escape.d.ts.map':
    '230a99e35af8c1a96bb303a6f649785d29ca23e9e688230641b931f1c1a5e365',
  'dist/commonjs/escape.js': '54b57f8f50c8e834f35a30c1848ac3f79acf8dd85894505f046afaf3965e63a0',
  'dist/commonjs/escape.js.map': 'b5f20d5a880214494df8a92d7cdec4e4d68b8b3470b81e4bf3c55f058bac6d28',
  'dist/commonjs/index.d.ts': '60d6bfd4f12c853ca58e0d1c7ff586a1e98cf999923c6bab006a4a376585fea1',
  'dist/commonjs/index.d.ts.map':
    '16a58b4fb83f563ef0729d4eb837996de715e084cef7e97ab12f4e90afe0dee3',
  'dist/commonjs/index.js': '00dae9725d5e8ec07bc366cd5e7f53c989d3e968b3d0c388e62903cb5d7bd7e0',
  'dist/commonjs/index.js.map': 'bb05ff5279ab024c9c67bcbc7d4df19b2442de996c6a219971e3d65920c76f87',
  'dist/commonjs/package.json': '8005a3491db7d92f36ac66369861589f9c47123d3a7c71e643fc2c06168cd45a',
  'dist/commonjs/unescape.d.ts': '7d3795e78cdc9079f6b03c6f85145f469582795af61134bbcf0568ae2e1476fe',
  'dist/commonjs/unescape.d.ts.map':
    'f9d8bff082045d428437be45a83e2a5c07cf1f3f4c3481a88779f1e24ecc76c5',
  'dist/commonjs/unescape.js': 'bec1bb4483a2c325599949dd6668b5b7daa2dcbe046c5a09899bc8c5b51c08c1',
  'dist/commonjs/unescape.js.map':
    '7a386a679c12ea329eca1c76d10db048489d3292c9a5658574e9307b89392b1b',
  'dist/esm/assert-valid-pattern.d.ts':
    'ff8872a24ed233ed9b80a521c1c5214ee996f4d649f537a1e8d12196d9f83d77',
  'dist/esm/assert-valid-pattern.d.ts.map':
    '6bda19e78c29faff99d261fb630e1b28ae01f61dd429861535834ae4fdbb9d59',
  'dist/esm/assert-valid-pattern.js':
    '90e8d3327d573b9d2391edf03dc7d50c1c0b468d720a4c0fb4a08a36ee5c50dc',
  'dist/esm/assert-valid-pattern.js.map':
    '83dd43a7bb36f95e216c8473f43f731d9ce2d1a27cfc5246226efb8a1d5232d9',
  'dist/esm/escape.d.ts': 'a7224113134dbd16bcf5e95e31b02f2d3da83aa99756a4b3cd133031670c72fc',
  'dist/esm/escape.d.ts.map': '230a99e35af8c1a96bb303a6f649785d29ca23e9e688230641b931f1c1a5e365',
  'dist/esm/escape.js': '8418e37c202bcd247e76b1c205d4eff9474f15fb76c1db1ef0688cb6a8ec3c94',
  'dist/esm/escape.js.map': 'd167494c1bc002ba3b3ae18bb41bc18b13a9f20631a3c24efe21f6394e107515',
  'dist/esm/index.d.ts': '60d6bfd4f12c853ca58e0d1c7ff586a1e98cf999923c6bab006a4a376585fea1',
  'dist/esm/index.d.ts.map': '16a58b4fb83f563ef0729d4eb837996de715e084cef7e97ab12f4e90afe0dee3',
  'dist/esm/index.js': 'b9d440e8e784f5cac857b76970b50dfa2ff4b1c0e9dfe143dfd546833b6567b7',
  'dist/esm/index.js.map': 'aa1ddf848d7e616bfa6b8171b918936f309b3991a124f4762e9a4e94b5060145',
  'dist/esm/package.json': '3ca9d4afd21425087cf31893b8f9f63c81b0b8408db5e343ca76e5f8aa26ab9a',
  'dist/esm/unescape.d.ts': '7d3795e78cdc9079f6b03c6f85145f469582795af61134bbcf0568ae2e1476fe',
  'dist/esm/unescape.d.ts.map': 'f9d8bff082045d428437be45a83e2a5c07cf1f3f4c3481a88779f1e24ecc76c5',
  'dist/esm/unescape.js': '2cd61ba96e616969f152445c61ec2ca129a0afd2028ea71309b862a4222304d6',
  'dist/esm/unescape.js.map': '11dca08b65b198c0a72baba3d8a866ff32f4875366e76d7205ca54b428bf39cf',
  'package.json': '0b5a1fdcbd7aa6905e5c56d1c50de03d52fa1dbd1ed48d62d4c2eb0675b4d43b',
};
function officialRelease() {
  assert.equal(JSON.parse(readFileSync(manifest, 'utf8')).version, '11.0.5');
  for (const [name, expected] of Object.entries(officialHashes))
    assert.equal(
      createHash('sha256')
        .update(readFileSync(join(installed, name)))
        .digest('hex'),
      expected,
      name,
    );
}

test('Installed minimatch is the complete unmodified official fixed release', () => {
  officialRelease();
  assert.equal(JSON.parse(readFileSync(manifest, 'utf8')).license, 'BlueOak-1.0.0');
});

// Bound the child even if a future dependency regression makes synchronous matching stall.
const probe = String.raw`
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const manifest = process.argv[1], kind = process.argv[2],
  metadata = JSON.parse(readFileSync(manifest, 'utf8')),
  local = createRequire(manifest),
  engine = kind === 'CJS' ? local('minimatch') :
    await import(pathToFileURL(resolve(dirname(manifest), metadata.exports['.'].import.default)).href),
  { Minimatch, minimatch, braceExpand } = engine,
  optimizationLevel = 2;
assert.equal(metadata.version, '11.0.5');
const atLimit = new Minimatch(Array(6).fill('**/../a/b').join('/'), {
  optimizationLevel, braceExpandMax: 64,
});
assert.equal(atLimit.set.length, 64);
for (const options of [{optimizationLevel, braceExpandMax:64}, {optimizationLevel}])
  assert.throws(() => new Minimatch(Array(30).fill('**/../a/b').join('/'), options),
    error => error instanceof RangeError && /too many patterns/.test(error.message));
const expanded = braceExpand('{a,b,c,d}{a,b,c,d}{a,b,c,d}{a,b,c,d}', {braceExpandMax:64});
assert.equal(expanded.length, 64);
assert.equal(new Set(expanded).size, 64);
assert.equal(expanded.every(value => /^[abcd]{4}$/.test(value)), true);
const small = new Minimatch('**/../a/b/**/../c/d', {optimizationLevel});
assert.equal(small.set.length, 4);
assert.equal(small.match('../a/b/../c/d'), true);
assert.equal(small.match('x/a/b/y/c/d'), true);
const alternatives = Array.from({length:1000}, (_, index) => 'a' + index),
  large = new Minimatch('{x,*}/{' + alternatives.join(',') + '}', {optimizationLevel});
assert.equal(large.match('x/a5'), true);
assert.equal(large.match('y/a999'), true);
assert.equal(large.match('.y/a5'), false);
assert.equal(large.match('y/missing'), false);
const pattern = Array(40).fill('**/a').join('/') + '/**/target.js',
  prefix = Array(40).fill('a').join('/'),
  partial = new Minimatch(pattern, {partial:true});
assert.equal(partial.match(prefix), true);
assert.equal(partial.match(prefix + '/.private'), false);
assert.equal(new Minimatch(pattern).match(prefix + '/target.js'), true);
for (const optimizationLevel of [0,1,2]) {
  assert.equal(minimatch('a/example.js', 'a/*.js', {optimizationLevel}), true);
  assert.equal(minimatch('a/example.ts', 'a/*.js', {optimizationLevel}), false);
  assert.equal(minimatch('a/.hidden.js', 'a/*.js', {optimizationLevel}), false);
}
assert.equal(minimatch('a/b/', 'a/b/*(x)'), false);
process.stdout.write(JSON.stringify({kind, atLimitAlternatives:64, amplificationRejected:true,
  largeAlternativeMatching:true, boundedPartialMatching:true, ordinaryMatching:true}) + '\n');
`;
for (const kind of ['ESM', 'CJS'])
  test(
    kind + ' official preprocessing and matching bounds preserve positive and negative semantics',
    { timeout: 15000 },
    () => {
      officialRelease();
      const result = spawnSync(
        process.execPath,
        ['--max-old-space-size=128', '--input-type=module', '--eval', probe, manifest, kind],
        {
          env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
          encoding: 'utf8',
          timeout: 10000,
          maxBuffer: 65536,
        },
      );
      assert.equal(result.error, undefined);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout), {
        kind,
        atLimitAlternatives: 64,
        amplificationRejected: true,
        largeAlternativeMatching: true,
        boundedPartialMatching: true,
        ordinaryMatching: true,
      });
    },
  );
