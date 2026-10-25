// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { extname, basename } from 'node:path';
import { createHash } from 'node:crypto';

const identifier = 'SPDX-License-Identifier: AGPL-3.0-or-later';
const copyright = 'Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>';
const paths = execFileSync(
  'git',
  ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
  {
    encoding: 'utf8',
  },
)
  .split('\0')
  .filter(Boolean);
let headers = 0,
  manifests = 0;
for (const path of paths) {
  const name = basename(path),
    extension = extname(path);
  if (name === 'package.json') {
    assert.equal(JSON.parse(readFileSync(path, 'utf8')).license, 'AGPL-3.0-or-later', path);
    manifests++;
  }
  const prefix = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'].includes(extension)
    ? '// '
    : (['.py', '.sh', '.yaml', '.yml', '.example'].includes(extension) &&
          name !== 'pnpm-lock.yaml') ||
        ['.gitignore', '.npmrc', '.prettierignore'].includes(name)
      ? '# '
      : undefined;
  if (!prefix) continue;
  const source = readFileSync(path, 'utf8');
  const body = source.startsWith('#!') ? source.slice(source.indexOf('\n') + 1) : source;
  assert.ok(body.startsWith(prefix + identifier + '\n' + prefix + copyright + '\n'), path);
  headers++;
}
assert.equal(
  createHash('sha256').update(readFileSync('LICENSE')).digest('hex'),
  '0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0',
  'LICENSE must preserve the reviewed upstream text exactly',
);
console.log(
  'License checks passed: ' +
    headers +
    ' authored source/configuration headers and ' +
    manifests +
    ' workspace manifests.',
);
