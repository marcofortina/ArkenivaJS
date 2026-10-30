// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { apiKeyFixture } from './api-key-fixture.js';

const grant = () => ({
  scopes: ['orders.read'],
  expiresAt: new Date(Date.now() + 60000).toISOString(),
});
test(
  'API key real OIDC authority and PostgreSQL preserve tenant ownership, rotation and immediate fresh-read revocation',
  { timeout: 30000 },
  async () => {
    const f = await apiKeyFixture();
    try {
      const a = await f.session(),
        b = await f.session({ tenant_id: 'tenant-b', sid: 'session-b' });
      await assert.rejects(f.first.keys.issue({ ...a.subject }, grant()));
      const issued = await a.run(() => f.first.keys.issue(a.subject, grant()));
      assert.equal((await f.second.keys.verify(issued.value, {})).keyId, issued.id);
      const other = await b.run(() => f.second.keys.issue(b.subject, grant()));
      assert.deepEqual(
        (await b.run(() => f.first.keys.list(b.subject))).map((row) => row.id),
        [other.id],
      );
      await assert.rejects(b.run(() => f.second.keys.rotate(issued.id, b.subject)));
      await assert.rejects(b.run(() => f.second.keys.revoke(issued.id, b.subject)));
      await assert.rejects(b.run(() => f.first.keys.list(a.subject)));
      const rotated = await a.run(() => f.second.keys.rotate(issued.id, a.subject));
      await assert.rejects(f.first.keys.verify(issued.value, {}));
      assert.equal((await f.first.keys.verify(rotated.value, {})).keyId, rotated.id);
      await a.run(() => f.first.keys.revoke(rotated.id, a.subject));
      await assert.rejects(f.second.keys.verify(rotated.value, {}));
      assert.deepEqual(await a.run(() => f.first.keys.list(a.subject)), []);
      const persisted = await f.backend.app.sql.query<{ body: string }>('main', {
        text: `SELECT body FROM ${f.backend.schema}.security_records`,
      });
      const content = JSON.stringify(persisted.rows);
      for (const secret of [
        issued.value.split('.')[2]!,
        rotated.value.split('.')[2]!,
        a.token,
        other.value.split('.')[2]!,
      ])
        assert.equal(content.includes(secret), false);
    } finally {
      await f.close();
    }
  },
);
test(
  'API key shared PostgreSQL quota and concurrent rotations admit one winner with no partial replacement',
  { timeout: 30000 },
  async () => {
    const f = await apiKeyFixture(1);
    try {
      const a = await f.session();
      f.synchronizeNextBatches(2);
      const issued = await a.run(() =>
        Promise.allSettled([
          f.first.keys.issue(a.subject, grant()),
          f.second.keys.issue(a.subject, grant()),
        ]),
      );
      assert.equal(issued.filter((result) => result.status === 'fulfilled').length, 1);
      const first = issued.find((result) => result.status === 'fulfilled')!;
      assert.equal(first.status, 'fulfilled');
      f.synchronizeNextBatches(2);
      const rotated = await a.run(() =>
        Promise.allSettled([
          f.first.keys.rotate(first.value.id, a.subject),
          f.second.keys.rotate(first.value.id, a.subject),
        ]),
      );
      assert.equal(rotated.filter((result) => result.status === 'fulfilled').length, 1);
      const winner = rotated.find((result) => result.status === 'fulfilled')!;
      assert.equal(winner.status, 'fulfilled');
      const rows = await a.run(() => f.second.keys.list(a.subject));
      assert.equal(rows.length, 1);
      assert.equal(rows[0]?.id, winner.value.id);
      await assert.rejects(f.first.keys.verify(first.value.value, {}));
      assert.equal((await f.second.keys.verify(winner.value.value, {})).keyId, winner.value.id);
    } finally {
      await f.close();
    }
  },
);
test(
  'API key signed session revocation, scope denial, secret provider outage and storage failure cannot bypass checks',
  { timeout: 30000 },
  async () => {
    const f = await apiKeyFixture();
    try {
      const a = await f.session(),
        issued = await a.run(() => f.first.keys.issue(a.subject, grant()));
      await assert.rejects(
        a.run(() => f.first.keys.issue(a.subject, { ...grant(), scopes: ['admin'] })),
      );
      f.revokeSession('session-a');
      await assert.rejects(a.run(() => f.second.keys.rotate(issued.id, a.subject)));
      f.state.authorityAvailable = false;
      await assert.rejects(f.first.keys.verify(issued.value, {}));
      f.state.authorityAvailable = true;
      f.state.secretAvailable = false;
      await assert.rejects(f.second.keys.verify(issued.value, {}));
      f.state.secretAvailable = true;
      assert.equal((await f.second.keys.verify(issued.value, {})).keyId, issued.id);
      await f.backend.app.sql.execute('main', {
        text: `DROP TABLE ${f.backend.schema}.security_records`,
      });
      await assert.rejects(f.first.keys.verify(issued.value, {}), (error) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_APIKEY_STORE');
        assert.equal(error.cause, undefined);
        return true;
      });
    } finally {
      await f.close();
    }
  },
);
test(
  'API key real durable owner index remains stable during HMAC rotation and source-network policy stays enforced',
  { timeout: 30000 },
  async () => {
    const f = await apiKeyFixture();
    try {
      const a = await f.session(),
        issued = await a.run(() =>
          f.first.keys.issue(a.subject, { ...grant(), allowedIpRanges: ['192.0.2.0/24'] }),
        );
      f.rotateHmac();
      assert.equal(
        (await f.second.keys.verify(issued.value, { clientIp: '192.0.2.15' })).keyId,
        issued.id,
      );
      await assert.rejects(f.first.keys.verify(issued.value, {}));
      await assert.rejects(f.second.keys.verify(issued.value, { clientIp: '198.51.100.2' }));
      assert.equal((await a.run(() => f.first.keys.list(a.subject))).length, 1);
      const rotated = await a.run(() => f.second.keys.rotate(issued.id, a.subject));
      assert.equal(
        (await f.first.keys.verify(rotated.value, { clientIp: '192.0.2.15' })).keyId,
        rotated.id,
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'API key real PostgreSQL corrupted record bodies fail closed and restored valid records remain usable',
  { timeout: 30000 },
  async () => {
    const f = await apiKeyFixture();
    try {
      const account = await f.session();
      const issued = await account.run(() => f.first.keys.issue(account.subject, grant()));
      const stored = await f.backend.app.sql.queryOne<{ body: string }>('main', {
        text: `SELECT body FROM ${f.backend.schema}.security_records WHERE namespace=:namespace AND id=:id`,
        bindings: { namespace: 'apikey.records.v1', id: issued.id },
      });
      assert.ok(stored);
      const original = JSON.parse(stored.body) as Record<string, unknown>;
      const write = (body: string) =>
        f.backend.app.sql.execute('main', {
          text: `UPDATE ${f.backend.schema}.security_records SET body=:body WHERE namespace=:namespace AND id=:id`,
          bindings: { body, namespace: 'apikey.records.v1', id: issued.id },
        });
      for (const patch of [
        { kind: 'unexpected-record' },
        { ownerKey: 'g'.repeat(64) },
        { createdAt: original.expiresAt },
      ]) {
        await write(JSON.stringify({ ...original, ...patch }));
        await assert.rejects(f.second.keys.verify(issued.value, {}), { code: 'EK_APIKEY_STORE' });
        await write(stored.body);
        assert.equal((await f.second.keys.verify(issued.value, {})).keyId, issued.id);
      }
      await account.run(() => f.first.keys.revoke(issued.id, account.subject));
      await assert.rejects(f.second.keys.verify(issued.value, {}));
    } finally {
      await f.close();
    }
  },
);
