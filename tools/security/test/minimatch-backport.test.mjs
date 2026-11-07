// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { after, before, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const workspace = fileURLToPath(new URL('../../../', import.meta.url));
const require = createRequire(import.meta.url);
const eslintRequire = createRequire(require.resolve('eslint/package.json'));
const installed = dirname(eslintRequire.resolve('minimatch/package.json'));
const patch = join(workspace, 'packages/graphql/compat/minimatch-bounded-globparts.diff');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const sourceSha = '7fee7388c3059d70573b3e4de77a05ae7b139d53ff855b5f6384659c5ff0a504';
const originalHashes = {
  'dist/esm/index.js': '59821ec2ce0d3df968292036e5c831ad322b33e9c33a949ecbc9dfe125d165be',
  'dist/commonjs/index.js': 'd224f71f20d7c206fcc5b7e9f747324c7698345a0b2c28d717dd9cf698306783',
  'dist/esm/index.js.map': '5c3e65c473cad1e082a2bcf0c8d40c63d4b72efe239906380515b33a5023a384',
  'dist/commonjs/index.js.map': '4345abdf627c9208d8c34f654a03a3ee3378a10c5241c7e434f8048db21b8240',
  'dist/esm/index.d.ts': '4a3fbf9bb0ebcae246f172ba1f5df33404a4dc0fde03a5241434889b1ca595a5',
  'dist/commonjs/index.d.ts': '4a3fbf9bb0ebcae246f172ba1f5df33404a4dc0fde03a5241434889b1ca595a5',
  'dist/esm/index.d.ts.map': '17bddd11b7c36d9588648943fc18fc17578d09226b14db02b4a12fb74178f1d1',
  'dist/commonjs/index.d.ts.map':
    '17bddd11b7c36d9588648943fc18fc17578d09226b14db02b4a12fb74178f1d1',
};
// Exact runtime edits from signed upstream commit 77a0f5c, without unrelated v11 changes.
const edits = [
  [
    '  firstPhasePreProcess(globParts: string[][]) {\n',
    '  firstPhasePreProcess(globParts: string[][]) {\n' +
      '    // each **/.. split doubles the patterns, so stop at the brace max\n' +
      '    const { braceExpandMax = 100_000 } = this.options\n',
  ],
  [
    "            p2 === '..'\n",
    "            p2 === '..' ||\n            globParts.length >= braceExpandMax\n",
  ],
  [
    '  secondPhasePreProcess(globParts: string[][]): string[][] {\n',
    '  secondPhasePreProcess(globParts: string[][]): string[][] {\n' +
      '    // each pattern is compared to each other one, so skip this for\n' +
      '    // large sets. The patterns match the same paths either way.\n' +
      '    if (globParts.length > 1000) return globParts\n',
  ],
];
function replaceOnce(source, from, to) {
  assert.equal(source.split(from).length, 2, 'Upstream patch context must be unique');
  return source.replace(from, to);
}
function generate(sources) {
  const result = new Map();
  for (const [folder, module] of [
    ['esm', ts.ModuleKind.ESNext],
    ['commonjs', ts.ModuleKind.CommonJS],
  ]) {
    const options = {
      module,
      target: ts.ScriptTarget.ES2022,
      strict: true,
      skipLibCheck: true,
      moduleResolution: ts.ModuleResolutionKind.Node10,
      ignoreDeprecations: '6.0',
      rootDir: join(installed, 'src'),
      outDir: join(installed, 'dist', folder),
      sourceMap: true,
      inlineSources: true,
      declaration: true,
      declarationMap: true,
      types: ['node'],
      typeRoots: [join(workspace, 'node_modules/@types')],
    };
    const host = ts.createCompilerHost(options);
    const read = host.readFile.bind(host),
      exists = host.fileExists.bind(host),
      directory = host.directoryExists.bind(host);
    host.readFile = (path) => sources.get(path) ?? read(path);
    host.fileExists = (path) => sources.has(path) || exists(path);
    host.directoryExists = (path) => path === join(installed, 'src') || directory(path);
    host.writeFile = (path, value) => result.set(path.slice(installed.length + 1), value);
    const program = ts.createProgram([...sources.keys()], options, host);
    assert.deepEqual(
      ts.getPreEmitDiagnostics(program).map((item) => item.code),
      [],
      'Baseline source must compile without diagnostics',
    );
    assert.equal(program.emit(undefined, host.writeFile, undefined, true).emitSkipped, false);
    const emitted = ts.transpileModule(sources.get(join(installed, 'src/index.ts')), {
      fileName: join(installed, 'src/index.ts'),
      compilerOptions: options,
    });
    result.set(`dist/${folder}/index.js`, emitted.outputText);
    result.set(`dist/${folder}/index.js.map`, emitted.sourceMapText);
  }
  return result;
}
let temporary, fixture, modules;
before(async () => {
  assert.equal(JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8')).version, '10.2.6');
  assert.equal(ts.version, '6.0.3');
  const sources = new Map();
  for (const name of readdirSync(join(installed, 'dist/esm')).filter((name) =>
    name.endsWith('.js.map'),
  )) {
    const map = JSON.parse(readFileSync(join(installed, 'dist/esm', name), 'utf8'));
    map.sources.forEach((path, index) =>
      sources.set(resolve(installed, 'dist/esm', path), map.sourcesContent[index]),
    );
  }
  const index = join(installed, 'src/index.ts');
  let baseline = sources.get(index);
  if (sha(baseline) !== sourceSha)
    for (const [from, to] of edits) baseline = replaceOnce(baseline, to, from);
  assert.equal(
    sha(baseline),
    sourceSha,
    'Original embedded source must match the official 10.2.6 artifact',
  );
  sources.set(index, baseline);
  const original = generate(sources);
  for (const [path, digest] of Object.entries(originalHashes))
    assert.equal(sha(original.get(path)), digest, path);
  sources.set(
    index,
    edits.reduce((source, [from, to]) => replaceOnce(source, from, to), baseline),
  );
  const corrected = generate(sources);
  // Public declarations remain byte-identical; declaration maps follow the corrected source lines.
  for (const folder of ['esm', 'commonjs'])
    assert.equal(
      corrected.get(`dist/${folder}/index.d.ts`),
      original.get(`dist/${folder}/index.d.ts`),
    );
  const installedKind =
    sha(readFileSync(join(installed, 'dist/esm/index.js'))) === originalHashes['dist/esm/index.js']
      ? original
      : corrected;
  for (const path of Object.keys(originalHashes))
    assert.equal(
      readFileSync(join(installed, path), 'utf8'),
      installedKind.get(path),
      'Installed artifact must be wholly original or wholly reviewed',
    );
  temporary = mkdtempSync(join(tmpdir(), 'arkenivajs-minimatch-backport-'));
  fixture = join(temporary, 'package');
  cpSync(installed, fixture, {
    recursive: true,
    filter: (path) => !path.startsWith(join(installed, 'node_modules')),
  });
  symlinkSync(join(installed, '..'), join(fixture, 'node_modules'), 'dir');
  for (const path of Object.keys(originalHashes))
    writeFileSync(join(fixture, path), original.get(path));
  const applied = spawnSync(
    'patch',
    ['--batch', '--forward', '--fuzz=0', '-p1', '--input', patch],
    { cwd: fixture, encoding: 'utf8', timeout: 10000 },
  );
  assert.equal(applied.status, 0, applied.stdout + applied.stderr);
  for (const path of Object.keys(originalHashes))
    assert.equal(
      readFileSync(join(fixture, path), 'utf8'),
      corrected.get(path),
      'Patched code, embedded source and maps must equal exact TypeScript emission',
    );
  modules = [
    ['ESM', await import(pathToFileURL(join(fixture, 'dist/esm/index.js')).href)],
    ['CJS', require(join(fixture, 'dist/commonjs/index.js'))],
  ];
});
after(() => {
  if (temporary) rmSync(temporary, { recursive: true, force: true });
});

test('Backport touches only the six regenerated runtime and source-map artifacts', () => {
  const paths = [...readFileSync(patch, 'utf8').matchAll(/^diff --git a\/(\S+) b\/(\S+)$/gm)];
  const expected = ['commonjs', 'esm'].flatMap((folder) =>
    ['.js', '.js.map', '.d.ts.map'].map((suffix) => `dist/${folder}/index${suffix}`),
  );
  assert.deepEqual(
    paths.map((match) => match[1]),
    expected,
  );
  assert.ok(paths.every((match) => match[1] === match[2]));
});

for (const kind of ['ESM', 'CJS']) {
  test(`${kind} upstream preprocessing bounds stop generated alternatives and preserve matching`, () => {
    const { Minimatch } = modules.find(([name]) => name === kind)[1];
    const optimizationLevel = 2,
      pattern = Array(30).fill('**/../a/b').join('/');
    assert.equal(new Minimatch(pattern, { optimizationLevel, braceExpandMax: 64 }).set.length, 64);
    assert.equal(new Minimatch(pattern, { optimizationLevel }).set.length, 100_000);
    const small = new Minimatch('**/../a/b/**/../c/d', { optimizationLevel });
    assert.equal(small.set.length, 4);
    assert.equal(small.match('../a/b/../c/d'), true);
    assert.equal(small.match('x/a/b/y/c/d'), true);
  });
  test(`${kind} upstream large-set guard preserves alternatives and negative dot matching`, () => {
    const { Minimatch } = modules.find(([name]) => name === kind)[1],
      optimizationLevel = 2;
    assert.equal(new Minimatch('{x,*}/{0..9}', { optimizationLevel }).set.length, 10);
    const large = new Minimatch('{x,*}/{0..999}', { optimizationLevel });
    assert.equal(large.set.length, 2000);
    assert.equal(large.match('x/5'), true);
    assert.equal(large.match('y/999'), true);
    assert.equal(large.match('.y/5'), false);
  });
  test(`${kind} retains v10 regex, AST, debug and ordinary matching APIs`, (context) => {
    const { minimatch, Minimatch, AST, makeRe } = modules.find(([name]) => name === kind)[1];
    assert.ok(AST.fromGlob('a*').toMMPattern() instanceof RegExp);
    assert.ok(makeRe('a/*.js') instanceof RegExp);
    assert.equal(makeRe('a/*.js').test('a/example.js'), true);
    const matcher = new Minimatch('a/*.js');
    assert.ok(matcher.makeRe() instanceof RegExp);
    assert.equal(matcher.regexp, matcher.makeRe());
    assert.equal(matcher.match('a/example.js'), true);
    assert.equal(matcher.match('a/example.ts'), false);
    assert.equal(matcher.match('a/.hidden.js'), false);
    assert.ok(matcher.set[0][1] instanceof RegExp);
    const logging = context.mock.method(console, 'error', () => {});
    const debug = new Minimatch('a/*.js', { debug: true });
    assert.equal(debug.match('a/example.js'), true);
    assert.ok(logging.mock.callCount() > 0);
    for (const optimizationLevel of [0, 1]) {
      assert.equal(minimatch('a/example.js', 'a/*.js', { optimizationLevel }), true);
      assert.equal(minimatch('a/example.ts', 'a/*.js', { optimizationLevel }), false);
    }
    assert.equal(minimatch('a/example.js', 'a/*.js'), true);
    assert.equal(minimatch('a/example.ts', 'a/*.js'), false);
  });
}
