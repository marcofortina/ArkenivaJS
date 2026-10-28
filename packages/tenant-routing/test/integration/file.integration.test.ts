// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { tenantRegistryFileProvider } from '../../dist/index.js';

test('An unprivileged application reads a root-owned production registry in an isolated deployment', async () => {
  assert.equal(process.env.ARKENIVA_TENANT_FILE_DISPOSABLE, '1');
  assert.notEqual(process.getuid?.(), 0);
  const root = process.env.ARKENIVA_TENANT_FILE_ROOT;
  assert.match(root ?? '', /^\/run\/arkenivajs-tenant-file-[a-z0-9-]+$/);
  const valid = join(root!, 'valid.json');
  assert.equal((await lstat(valid)).uid, 0);
  const provider = tenantRegistryFileProvider({ absolutePath: valid, maxBytes: 1048576 });
  assert.equal((await provider.loadSnapshot()).revision, 'isolated-deployment');
  for (const file of ['public.json', 'untrusted-owner.json', 'writable/registry.json', 'link.json'])
    await assert.rejects(
      tenantRegistryFileProvider({
        absolutePath: join(root!, file),
        maxBytes: 1048576,
      }).loadSnapshot(),
      { code: 'EK_TROUTE_REGISTRY', message: 'Invalid tenant routing registry' },
    );
});
