// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readdir, readFile, writeFile, mkdir, mkdtemp, chmod, cp, rm } from 'node:fs/promises';
import { dirname, join, delimiter } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { packPackage } from './pack.mjs';
import { parse as parseYaml, parseAllDocuments } from 'yaml';
import {
  selectTestFiles,
  snapshotReviewedPatches,
  resolvedPatches,
} from './packed-example-inputs.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
assert.ok(
  args.length === 0 ||
    (args.length === 2 && ['--example', '--integration', '--browser'].includes(args[0])),
  'Use --example EXAMPLE, --integration EXAMPLE or --browser EXAMPLE to select a suite',
);
const selected = args[1];
const nativeKafka = args[0] === '--integration' && selected === 'kafka';
if (nativeKafka)
  assert.equal(
    process.env.ARKENIVA_KAFKA_DISPOSABLE,
    '1',
    'Native Kafka builds require an explicitly disposable environment',
  );
const selectedScript =
  args[0] === '--example' ? 'test' : args[0] === '--browser' ? 'test:browser' : 'test:integration';
if (selected) assert.match(selected, /^[a-z][a-z0-9-]*$/);
const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-packed-examples-'));
await chmod(directory, 0o700);
function execute(command, arguments_, cwd, timeout = 180000, env = process.env) {
  const result = spawnSync(command, arguments_, { cwd, stdio: 'inherit', timeout, env });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'Packed example verification failed');
}
const examples = [];
try {
  const archiveDirectory = join(directory, 'packages');
  await mkdir(archiveDirectory, { mode: 0o700 });
  const workspace = parseYaml(await readFile(join(root, 'pnpm-workspace.yaml'), 'utf8')),
    dependencies = {},
    overrides = workspace.overrides ?? {},
    archives = new Map();
  for (const [selector, version] of Object.entries(overrides)) {
    assert.match(selector, /^[a-z@][a-z0-9@/.*>^~-]+$/);
    assert.match(version, /^\d+\.\d+\.\d+$/);
  }
  const tooling = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  dependencies['@types/node'] = tooling.devDependencies['@types/node'];
  await cp(join(root, 'tsconfig.base.json'), join(directory, 'tsconfig.base.json'));
  for (const folder of (await readdir(join(root, 'packages'))).sort()) {
    const location = join(root, 'packages', folder),
      manifest = JSON.parse(await readFile(join(location, 'package.json'), 'utf8'));
    await packPackage(location, archiveDirectory);
    const archive = join(
      archiveDirectory,
      manifest.name.replace('@', '').replace('/', '-') + '-' + manifest.version + '.tgz',
    );
    dependencies[manifest.name] = 'file:' + archive;
    overrides[manifest.name] = 'file:' + archive;
    archives.set(folder, { archive, manifest });
  }
  const patches = await snapshotReviewedPatches({
    patches: workspace.patchedDependencies ?? {},
    archives,
    root,
    directory,
  });
  for (const folder of (await readdir(join(root, 'examples'))).sort()) {
    if (selected && folder !== selected) continue;
    const original = join(root, 'examples', folder),
      target = join(directory, 'examples', folder),
      manifest = JSON.parse(await readFile(join(original, 'package.json'), 'utf8'));
    assert.ok(manifest.scripts.test, 'Every example needs an executable test');
    if (selected)
      assert.ok(
        manifest.scripts[selectedScript],
        'The selected example has no requested live suite',
      );
    await mkdir(target, { recursive: true, mode: 0o700 });
    await cp(join(original, 'dist'), join(target, 'dist'), { recursive: true, errorOnExist: true });
    await cp(join(original, 'dist-test'), join(target, 'dist-test'), {
      recursive: true,
      errorOnExist: true,
    });
    for (const name of ['src', 'test', 'tsconfig.json', 'tsconfig.test.json'])
      await cp(join(original, name), join(target, name), { recursive: true, errorOnExist: true });
    // Preserve example-relative paths while forcing every framework import through a packed artifact.
    await writeFile(
      join(target, 'package.json'),
      JSON.stringify({ name: manifest.name, private: true, type: 'module' }),
    );
    for (const [name, version] of Object.entries({
      ...manifest.dependencies,
      ...manifest.devDependencies,
    })) {
      if (!name.startsWith('@arkenivajs/')) {
        assert.ok(
          !dependencies[name] || dependencies[name] === version,
          'Examples require consistent external dependency pins',
        );
        dependencies[name] = version;
      }
    }
    examples.push({ target, script: manifest.scripts[selected ? selectedScript : 'test'] });
  }
  assert.ok(examples.length > 0, 'No executable examples selected');
  await writeFile(
    join(directory, 'package.json'),
    JSON.stringify({
      name: 'packed-example-verification',
      private: true,
      type: 'module',
      packageManager: tooling.packageManager,
      dependencies,
    }),
  );
  const configuration =
    'packages: []\noverrides:\n' +
    Object.entries(overrides)
      .map(([name, value]) => '  ' + JSON.stringify(name) + ': ' + JSON.stringify(value))
      .join('\n') +
    '\n';
  await writeFile(join(directory, 'pnpm-workspace.yaml'), configuration);
  // Resolve without installing code, then apply exactly the reviewed patches present in this graph.
  execute(
    'pnpm',
    ['install', '--ignore-scripts', '--lockfile-only', '--no-frozen-lockfile'],
    directory,
  );
  const activePatches = resolvedPatches(
    patches,
    parseAllDocuments(await readFile(join(directory, 'pnpm-lock.yaml'), 'utf8')).map((document) =>
      document.toJS(),
    ),
  );
  await writeFile(
    join(directory, 'pnpm-workspace.yaml'),
    configuration +
      'patchedDependencies:\n' +
      Object.entries(activePatches)
        .map(([name, value]) => '  ' + JSON.stringify(name) + ': ' + JSON.stringify(value))
        .join('\n') +
      '\n',
  );
  // This isolated graph is created here, so resolve its patch hashes before
  // requiring an immutable installation under the same policy used by CI.
  execute(
    'pnpm',
    ['install', '--ignore-scripts', '--lockfile-only', '--no-frozen-lockfile'],
    directory,
  );
  execute('pnpm', ['install', '--ignore-scripts', '--frozen-lockfile'], directory);
  if (nativeKafka) {
    await writeFile(
      join(directory, 'pnpm-workspace.yaml'),
      (await readFile(join(directory, 'pnpm-workspace.yaml'), 'utf8')) +
        "allowBuilds:\n  '@confluentinc/kafka-javascript@1.11.0': true\n",
    );
    execute('pnpm', ['rebuild', '@confluentinc/kafka-javascript'], directory, 600000, {
      ...process.env,
      MAKEFLAGS: '-j2',
      npm_config_jobs: '2',
    });
  }
  console.log('Applied reviewed compatibility diffs: ' + Object.keys(activePatches).length);
  for (const example of examples) {
    for (const configuration of ['tsconfig.json', 'tsconfig.test.json'])
      execute(
        process.execPath,
        [join(root, 'node_modules/typescript/bin/tsc'), '-p', configuration],
        example.target,
      );
    assert.match(example.script, /^node --test(?: --test-reporter=spec)? [a-z0-9/*.-]+$/);
    const flags = example.script.slice('node '.length).split(' '),
      pattern = flags.pop(),
      location = dirname(pattern),
      files = selectTestFiles(pattern, await readdir(join(example.target, location)));
    assert.ok(files.length > 0, 'The selected example must contain executable tests');
    if (selected === 'xml' && selectedScript === 'test:integration')
      execute(
        'python3',
        [join(example.target, 'test/fixtures/run.py'), '--', process.execPath, ...flags, ...files],
        example.target,
      );
    else
      // Direct Node execution retains example-relative files while exposing
      // commands installed in the isolated consumer, as a package script does.
      execute(process.execPath, [...flags, ...files], example.target, 180000, {
        ...process.env,
        PATH: join(directory, 'node_modules', '.bin') + delimiter + (process.env.PATH ?? ''),
      });
  }
  console.log('Packed public artifacts passed ' + examples.length + ' executable example suites.');
} finally {
  await rm(directory, { recursive: true, force: true });
}
