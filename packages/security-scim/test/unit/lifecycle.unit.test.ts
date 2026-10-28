// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Runtime } from '../../dist/runtime.js';
import { managed } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';
import { createScimService } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test('Cancelled provider work retains capacity until it physically settles and reports uncertain mutation outcomes', async () => {
  const runtime = new Runtime(undefined, undefined, 1),
    abort = new AbortController();
  let release!: () => void, entered!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const actual = runtime.run({ signal: abort.signal }, (call) =>
    call.mutate(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
          entered();
        }),
    ),
  );
  const rejected = assert.rejects(actual, { code: 'EK_ABORTED', details: { outcome: 'unknown' } });
  await started;
  abort.abort();
  await rejected;
  await assert.rejects(
    runtime.run(undefined, async () => undefined),
    { code: 'EK_BACKEND_UNAVAILABLE' },
  );
  const closing = runtime.close();
  release();
  await closing;
  await runtime.close();
  await assert.rejects(
    runtime.run(undefined, async () => undefined),
    { code: 'EK_RESOURCE_CLOSED' },
  );
});

test('Readiness, duplicate registration and closed service ownership are enforced independently', async () => {
  const f = await fixture();
  let ready = false;
  const owner = managed(capture(f.settings), undefined, () => ready);
  try {
    owner.service.registerUsers(f.provider('Users'));
    assert.throws(() => owner.service.registerUsers(f.provider('Users')), {
      code: 'EK_LIFECYCLE_STATE',
    });
    const request = await f.request('GET', '/Users');
    await assert.rejects(owner.service.handle(request), { code: 'EK_LIFECYCLE_STATE' });
    ready = true;
    assert.equal((await owner.service.handle(request)).status, 200);
    await owner.close();
    await assert.rejects(owner.service.handle(request), { code: 'EK_RESOURCE_CLOSED' });
  } finally {
    await owner.close();
    await f.close();
  }
});

test('Production rejects test-only storage and authority, including inherited markers and accessor traps', async () => {
  const f = await fixture();
  try {
    for (const environment of ['production', 'development'] as const) {
      const service = createScimService({ ...f.settings, environment });
      assert.throws(() => service.registerUsers(f.provider('Users')), {
        code: 'EK_CONFIG_INVALID',
      });
      assert.throws(
        () =>
          createScimService({
            ...f.settings,
            environment,
            authority: Object.assign(
              Object.create({ usage: 'test-only' }),
              f.authority,
            ) as typeof f.authority,
          }),
        { code: 'EK_CONFIG_INVALID' },
      );
    }
    const authority = { ...f.authority };
    Object.defineProperty(authority, 'usage', {
      get() {
        throw new Error('The provider marker accessor ran');
      },
    });
    assert.throws(
      () => createScimService({ ...f.settings, environment: 'production', authority }),
      { code: 'EK_CONFIG_INVALID' },
    );
    for (const change of [
      { maxPageSize: 0 },
      { maxPageSize: 1001 },
      { maxFilterDepth: 17 },
      { environment: 'unknown' },
      { unknown: true },
    ])
      assert.throws(() => createScimService({ ...f.settings, ...change } as never), {
        code: 'EK_CONFIG_INVALID',
      });
  } finally {
    await f.close();
  }
});

test('Malformed acknowledgements after a real write report an unknown outcome rather than a client validation error', async () => {
  const f = await fixture(),
    owner = managed(capture(f.settings));
  try {
    const backend = f.provider('Users');
    owner.service.registerUsers({
      ...backend,
      async create(...args) {
        await backend.create(...args);
        return { id: 'invalid', schemas: [] };
      },
    });
    const request = await f.request('POST', '/Users', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'late-acknowledgement',
    });
    const result = await owner.service.handle(request);
    assert.equal(result.status, 503);
    assert.match(JSON.stringify(result.body), /outcome is unknown/);
    assert.equal((await f.service.handle(await f.request('GET', '/Users'))).status, 200);
  } finally {
    await owner.close();
    await f.close();
  }
});
