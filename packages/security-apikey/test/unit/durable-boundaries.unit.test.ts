// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { application, fixtureSettings, grant } from './fixture.js';
import type { ApiKeyPolicy } from '../../dist/index.js';

const storeFailure = { code: 'EK_APIKEY_STORE' };

test('API key persisted record discriminators, owner indexes and validity intervals reject corruption before authorization', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant());
    const entry = JSON.stringify(['apikey.records.v1', issued.id]),
      original = f.rows.get(entry)!;
    for (const change of [
      { kind: 'unexpected-record' },
      { id: randomUUID() },
      { ownerKey: 'g'.repeat(64) },
      { createdAt: original.expiresAt },
      {
        policy: {
          ...(original.policy as ApiKeyPolicy),
          expiresAt: new Date(Date.parse(String(original.expiresAt)) + 1000).toISOString(),
        },
      },
    ]) {
      f.rows.set(entry, { ...original, ...change });
      const before = f.state.calls.length;
      await assert.rejects(keys.verify(issued.value, {}), storeFailure);
      assert.equal(f.state.calls.length, before);
      f.rows.set(entry, original);
      assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
    }
  } finally {
    await app.stop();
  }
});

test('API key owner guard and durable verification counter corruption never grants a key or a verification', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant());
    await keys.verify(issued.value, {});
    const guard = [...f.rows.entries()].find(([, row]) => row.kind === 'api-key-owner-v1')!;
    for (const patch of [{ kind: 'wrong-guard' }, { ownerKey: '0'.repeat(64) }]) {
      f.rows.set(guard[0], { ...guard[1], ...patch });
      await assert.rejects(keys.issue(f.owner, grant()), storeFailure);
      f.rows.set(guard[0], guard[1]);
    }
    const rate = [...f.rows.entries()].find(([key]) => JSON.parse(key)[1].startsWith('verify-'))!;
    for (const patch of [
      { kind: 'wrong-counter' },
      { ownerKey: '0'.repeat(64) },
      { minute: -1 },
      { count: 0 },
      { count: 100001 },
      { expiresAt: new Date(Date.now() + 600000).toISOString() },
    ]) {
      f.rows.set(rate[0], { ...rate[1], ...patch });
      await assert.rejects(keys.verify(issued.value, {}), storeFailure);
      f.rows.set(rate[0], rate[1]);
    }
    assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
    assert.equal((await keys.list(f.owner)).length, 1);
  } finally {
    await app.stop();
  }
});

test('API key malformed compare-and-set acknowledgments cannot be accepted as persisted rate admission', async () => {
  for (const receipt of [undefined, {}, { committed: 'true' }, { committed: true, version: '' }]) {
    const f = fixtureSettings();
    f.store.compareAndSet = async () => receipt as never;
    const { app, keys } = await application(f.settings);
    try {
      await assert.rejects(keys.issue(f.owner, grant()), storeFailure);
      assert.equal([...f.rows.values()].filter((row) => row.kind === 'api-key-v1').length, 0);
    } finally {
      await app.stop();
    }
  }
});

test('API key indexed accessor rows and inconsistent owner metadata never return a partial list', async () => {
  const f = fixtureSettings(),
    list = f.store.listByOwner;
  let mode = '';
  f.store.listByOwner = async (...args) => {
    const rows = await Reflect.apply(list, f.store, args);
    if (!mode) return rows;
    if (mode === 'accessor')
      return Object.defineProperty(new Array(1), '0', {
        get() {
          throw new Error('An indexed accessor must not execute');
        },
      });
    return rows.map((row) => ({ ...row, ownerKey: '0'.repeat(64) }));
  };
  const { app, keys } = await application(f.settings);
  try {
    await keys.issue(f.owner, grant());
    for (mode of ['accessor', 'foreign-owner'])
      await assert.rejects(keys.list(f.owner), storeFailure);
    mode = '';
    assert.equal((await keys.list(f.owner)).length, 1);
  } finally {
    await app.stop();
  }
});

test('API keys reject cryptographically valid expired rows even when storage has not purged them', async () => {
  const f = fixtureSettings(),
    read = f.store.read;
  let expired = false;
  f.store.read = async (...args) => {
    const row = await Reflect.apply(read, f.store, args);
    if (!expired || args[0] !== 'apikey.records.v1' || row === null) return row;
    const expiresAt = new Date(Date.now() - 60000).toISOString();
    return {
      ...row,
      expiresAt,
      createdAt: new Date(Date.now() - 120000).toISOString(),
      policy: { ...(row.policy as ApiKeyPolicy), expiresAt },
    };
  };
  const { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant());
    expired = true;
    await assert.rejects(keys.verify(issued.value, {}), { code: 'EK_APIKEY_EXPIRED' });
    await assert.rejects(keys.rotate(issued.id, f.owner), { code: 'EK_APIKEY_EXPIRED' });
    expired = false;
    assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
  } finally {
    await app.stop();
  }
});

test('API key operations reject own signal overrides before provider work', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    for (const name of ['aborted', 'reason', 'addEventListener', 'removeEventListener']) {
      const signal = new AbortController().signal;
      Object.defineProperty(signal, name, {
        get() {
          throw new Error('Signal metadata must not execute');
        },
      });
      const before = f.state.calls.length;
      await assert.rejects(keys.list(f.owner, { signal }), { code: 'EK_CONFIG_INVALID' });
      assert.equal(f.state.calls.length, before);
    }
  } finally {
    await app.stop();
  }
});

test('API key operation ownership sanitizes unexpected work failures and enforces a real monotonic deadline', async () => {
  const { runtime, captureSettings } = await import('../../dist/runtime.js');
  const f = fixtureSettings(),
    owner = runtime(captureSettings(f.settings));
  try {
    await assert.rejects(
      owner.run(undefined, false, async () => {
        throw new Error('Private unexpected operation diagnostic');
      }),
      (error: unknown) => {
        assert.equal((error as { code?: string }).code, 'EK_APIKEY_INVALID');
        assert.ok(!String(error).includes('Private unexpected'));
        return true;
      },
    );
    await assert.rejects(
      owner.run({ timeoutMs: 5 }, false, async (call) => {
        const end = performance.now() + 10;
        while (performance.now() < end) {
          /* Retain the actual event loop until the monotonic deadline passes. */
        }
        call.check();
      }),
      { code: 'EK_TIMEOUT' },
    );
  } finally {
    owner.close();
  }
});
