// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { securityStateFixture } from '../../../../examples/postgres/dist-test/integration/security-state-fixture.js';
import { transactionFixture } from '../fixtures/transactions.js';

test(
  'Actual PostgreSQL atomically consumes protected federation state across independent instances',
  { timeout: 30000 },
  async () => {
    const backend = await securityStateFixture();
    const f = await transactionFixture({
      store: backend.store,
      securityLevel: 'test-only',
      operationTimeoutMs: 5000,
    });
    try {
      const created = await f.runtime.run((call) => f.first.create(call, f.input)),
        rows = await backend.app.sql.query<{ body: string }>('main', {
          text: `SELECT body FROM ${backend.schema}.security_records`,
        });
      assert.equal(rows.rows.length, 1);
      for (const value of [
        created.transactionId,
        created.verifier,
        created.nonce,
        created.tenantHint!,
      ])
        assert.equal(rows.rows[0]!.body.includes(value), false);
      const instances = [f.first, f.second, f.instance()],
        results = await Promise.allSettled(
          Array.from({ length: 8 }, (_, index) =>
            f.runtime.run((call) =>
              instances[index % instances.length]!.consume(
                call,
                created.transactionId,
                created.issuer,
              ),
            ),
          ),
        );
      assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
      const accepted = results.find((result) => result.status === 'fulfilled');
      assert.ok(accepted && accepted.status === 'fulfilled');
      assert.equal(accepted.value.verifier, created.verifier);
      await assert.rejects(
        () =>
          f.runtime.run((call) =>
            f.instance().consume(call, created.transactionId, created.issuer),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
      const claimed = await backend.app.sql.query<{ count: number }>('main', {
        text: `SELECT count(*)::integer AS count FROM ${backend.schema}.security_claims`,
      });
      assert.equal(claimed.rows[0]!.count, 1);
    } finally {
      await f.close();
      await backend.close();
    }
  },
);
test(
  'A lost acknowledgement after an actual PostgreSQL claim cannot produce success or enable replay',
  { timeout: 30000 },
  async () => {
    const backend = await securityStateFixture();
    const f = await transactionFixture({
      store: backend.store,
      securityLevel: 'test-only',
      operationTimeoutMs: 5000,
    });
    try {
      const created = await f.runtime.run((call) => f.first.create(call, f.input)),
        ambiguous = f.instance({
          ...f.settings,
          stateStore: {
            ...f.settings.stateStore,
            store: {
              ...backend.store,
              async claimOnce(...args) {
                await backend.store.claimOnce(...args);
                throw new Error('The fixture claim acknowledgement was lost');
              },
            },
          },
        });
      await assert.rejects(
        () =>
          f.runtime.run((call) => ambiguous.consume(call, created.transactionId, created.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
      await assert.rejects(
        () =>
          f.runtime.run((call) => f.second.consume(call, created.transactionId, created.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
      const claimed = await backend.app.sql.query<{ count: number }>('main', {
        text: `SELECT count(*)::integer AS count FROM ${backend.schema}.security_claims`,
      });
      assert.equal(claimed.rows[0]!.count, 1);
    } finally {
      await f.close();
      await backend.close();
    }
  },
);
