// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const script = fileURLToPath(new URL('../check-licenses.mjs', import.meta.url));
const license = readFileSync(new URL('../../LICENSE', import.meta.url));
const notices =
  'SPDX-License-Identifier: AGPL-3.0-or-later\n' +
  'Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>\n';
const header = (prefix) =>
  notices
    .split('\n')
    .filter(Boolean)
    .map((line) => prefix + line)
    .join('\n') + '\n';

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'arkenivajs-license-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const initialized = spawnSync('git', ['init', '--initial-branch=main', '--quiet', directory], {
    encoding: 'utf8',
  });
  assert.equal(initialized.status, 0, initialized.stderr);
  const write = (name, contents) => writeFileSync(join(directory, name), contents);
  write('LICENSE', license);
  write('package.json', JSON.stringify({ private: true, license: 'AGPL-3.0-or-later' }));
  const check = () => spawnSync(process.execPath, [script], { cwd: directory, encoding: 'utf8' });
  return { directory, write, check };
}

test('License checks require both notices on every JavaScript and TypeScript source format', (t) => {
  const { write, check } = fixture(t);
  for (const extension of ['ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs', 'cjs']) {
    const path = 'example.' + extension;
    write(path, '// SPDX-License-Identifier: AGPL-3.0-or-later\n');
    const rejected = check();
    assert.notEqual(rejected.status, 0, path);
    assert.ok(rejected.stderr.includes(path));
    write(path, header('// ') + 'export {};\n');
    const accepted = check();
    assert.equal(accepted.status, 0, accepted.stderr);
  }
});

test('License checks preserve shebang order and strict JSON and lockfile syntax', (t) => {
  const { write, check } = fixture(t);
  write('run.sh', '#!/usr/bin/env bash\n' + header('# ') + 'set -eu\n');
  write('cli.cjs', '#!/usr/bin/env node\n' + header('// ') + "'use strict';\n");
  write('schema.json', '{"type":"object","additionalProperties":false}\n');
  write('pnpm-lock.yaml', 'lockfileVersion: 12.0\n');
  assert.equal(check().status, 0);
  write('run.sh', '#!/usr/bin/env bash\nset -eu\n' + header('# '));
  const rejected = check();
  assert.notEqual(rejected.status, 0);
  assert.ok(rejected.stderr.includes('run.sh'));
});

test('License checks reject incompatible npm metadata and any license text mutation', (t) => {
  const { write, check } = fixture(t);
  write('package.json', JSON.stringify({ private: true, license: 'UNLICENSED' }));
  assert.notEqual(check().status, 0);
  write('package.json', JSON.stringify({ private: true, license: 'AGPL-3.0-or-later' }));
  write('LICENSE', Buffer.concat([license, Buffer.from('\n')]));
  const rejected = check();
  assert.notEqual(rejected.status, 0);
  assert.ok(rejected.stderr.includes('LICENSE must preserve the reviewed upstream text exactly'));
});
