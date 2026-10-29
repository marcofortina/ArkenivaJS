// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { capture } from '../../dist/policy.js';
import { policy, schema } from './fixture.js';

test('Multipart route validation preserves fixed paths, parameter characters and explicit trailing slashes', () => {
  const route = (path: string) => ({
    path,
    method: 'POST' as const,
    auth: { required: true as const },
    policy,
    responseSchema: schema,
    handler: async () => ({}),
  });
  for (const path of ['/', '/uploads', '/documents/v1', '/documents/:id', '/a.b_~-:0/', '/a/b/c'])
    assert.equal(capture({ routes: [route(path)] })[0]!.path, path);
  for (const path of [
    '//',
    '/a//b',
    '/.',
    '/a/..',
    '/readyz',
    '/livez',
    'uploads',
    '/🗂',
    '/a?x',
    '/a#x',
    '/a\n',
  ])
    assert.throws(() => capture({ routes: [route(path)] }), { code: 'EK_UPLOAD_CONFIG' });
});

test('Multipart rejects maximal malformed paths within an independently enforced process deadline', () => {
  const module = new URL('../../dist/policy.js', import.meta.url).href;
  const script = `
    import { capture } from ${JSON.stringify(module)};
    for (const path of ['/' + 'a'.repeat(1000) + '!', '/' + 'a/'.repeat(500) + '!']) {
      try {
        capture({routes:[{path, method:'POST', auth:{required:true}, policy:${JSON.stringify(policy)}, responseSchema:${JSON.stringify(schema)}, handler:async()=>({})}]});
        throw new Error('Malformed upload path was accepted');
      } catch (error) {
        if (error.code !== 'EK_UPLOAD_CONFIG') throw error;
      }
    }
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    timeout: 3000,
    encoding: 'utf8',
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});
