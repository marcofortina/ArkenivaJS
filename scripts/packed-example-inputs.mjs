// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { matchesGlob, join, dirname } from 'node:path';
import { lstat, readFile, mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

/** Execute the requested compiled suite, including integration files without a .test suffix. */
export function selectTestFiles(pattern, names) {
  assert.match(pattern, /^dist-test\/(?:[a-z0-9-]+\/)*[a-z0-9*.-]+\.js$/);
  const directory = dirname(pattern);
  const files = names
    .filter((name) => matchesGlob(join(directory, name), pattern))
    .sort()
    .map((name) => join(directory, name));
  assert.ok(files.length > 0, 'The requested packed example suite must contain executable tests');
  return files;
}

/** Test-only dependencies absent from an independent graph must not create unused-patch failures. */
export function resolvedPatches(patches, documents) {
  const resolved = new Set(documents.flatMap((document) => Object.keys(document?.packages ?? {})));
  return Object.fromEntries(Object.entries(patches).filter(([selector]) => resolved.has(selector)));
}

/** Carry only exact reviewed compatibility diffs whose source bytes match the packed artifact. */
export async function snapshotReviewedPatches({ patches, archives, root, directory }) {
  const result = {};
  await mkdir(join(directory, 'reviewed-compat'), { mode: 0o700 });
  for (const [selector, path] of Object.entries(patches)) {
    assert.match(selector, /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+@\d+\.\d+\.\d+$/);
    assert.equal(typeof path, 'string');
    const match = /^packages\/([a-z0-9-]+)\/(compat\/[a-z0-9_.-]+\.diff)$/.exec(path);
    assert.ok(match, 'Only packaged, reviewed compatibility diffs may enter an external consumer');
    const owner = archives.get(match[1]);
    assert.ok(owner?.manifest.files.includes('compat'));
    const source = join(root, path);
    assert.ok((await lstat(source)).isFile());
    const bytes = await readFile(source);
    assert.ok(bytes.length > 0 && bytes.length <= 1024 * 1024);
    const extracted = spawnSync('tar', ['-xOf', owner.archive, 'package/' + match[2]], {
      maxBuffer: 1024 * 1024,
    });
    assert.equal(
      extracted.status,
      0,
      'A reviewed compatibility diff is missing from its installed artifact',
    );
    assert.ok(
      bytes.equals(extracted.stdout),
      'Compatibility source differs from the exact packed artifact',
    );
    const relative = 'reviewed-compat/' + Object.keys(result).length + '.diff';
    await writeFile(join(directory, relative), bytes, { mode: 0o600, flag: 'wx' });
    result[selector] = relative;
  }
  return result;
}
