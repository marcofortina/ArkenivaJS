// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { securityStateFixture } from '../../../../examples/postgres/dist-test/integration/security-state-fixture.js';
import { transactionFixture } from '../fixtures/transactions.js';
import { capture } from '../../dist/settings.js';
import { FederationTransactions } from '../../dist/transactions.js';

test(
  'Actual PostgreSQL keeps SPID and CIE one-use state isolated under identical profile IDs and external keys',
  { timeout: 30000 },
  async () => {
    const backend = await securityStateFixture(),
      f = await transactionFixture({
        store: backend.store,
        securityLevel: 'test-only',
        operationTimeoutMs: 5000,
      });
    try {
      const profile = {
        ...f.profile,
        system: 'cie' as const,
        allowedAssurance: ['cie-l2' as const],
      };
      const cie = [backend.store, backend.peer].map(
        (store) =>
          new FederationTransactions(
            capture(
              {
                ...f.settings,
                profiles: [profile],
                stateStore: { ...f.settings.stateStore, store },
              },
              'test',
              'cie',
            ),
            profile.profileId,
            f.crypto,
          ),
      );
      const spidState = await f.runtime.run((call) => f.first.create(call, f.input)),
        cieState = await f.runtime.run((call) =>
          cie[0]!.create(call, { ...f.input, assurance: 'cie-l2' }),
        );
      await assert.rejects(
        () =>
          f.runtime.run((call) => cie[1]!.consume(call, spidState.transactionId, spidState.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
      await assert.rejects(
        () =>
          f.runtime.run((call) => f.second.consume(call, cieState.transactionId, cieState.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
      const before = await backend.app.sql.query<{ count: number }>('main', {
        text: `SELECT count(*)::integer AS count FROM ${backend.schema}.security_claims`,
      });
      assert.equal(before.rows[0]!.count, 0);
      const rows = await backend.app.sql.query<{
        namespace: string;
        owner_key: string;
        body: string;
      }>('main', {
        text: `SELECT namespace,owner_key,body FROM ${backend.schema}.security_records ORDER BY namespace`,
      });
      assert.deepEqual(
        rows.rows.map((row) => row.namespace),
        ['arkenivajs.cie.authorization.v1', 'arkenivajs.spid.authorization.v1'],
      );
      assert.notEqual(rows.rows[0]!.owner_key, rows.rows[1]!.owner_key);
      for (const row of rows.rows)
        for (const state of [spidState, cieState])
          for (const secret of [state.transactionId, state.nonce, state.verifier])
            assert.equal(row.body.includes(secret), false);
      const outcomes = await Promise.all([
        Promise.allSettled(
          Array.from({ length: 4 }, (_, index) =>
            f.runtime.run((call) =>
              (index % 2 ? f.first : f.second).consume(
                call,
                spidState.transactionId,
                spidState.issuer,
              ),
            ),
          ),
        ),
        Promise.allSettled(
          Array.from({ length: 4 }, (_, index) =>
            f.runtime.run((call) =>
              cie[index % 2]!.consume(call, cieState.transactionId, cieState.issuer),
            ),
          ),
        ),
      ]);
      for (const [index, results] of outcomes.entries()) {
        const successes = results.filter((result) => result.status === 'fulfilled');
        assert.equal(successes.length, 1);
        assert.equal(successes[0]!.value.assurance, index === 0 ? 'spid-l2' : 'cie-l2');
      }
      const after = await backend.app.sql.query<{ count: number }>('main', {
        text: `SELECT count(*)::integer AS count FROM ${backend.schema}.security_claims`,
      });
      assert.equal(after.rows[0]!.count, 2);
    } finally {
      await f.close();
      await backend.close();
    }
  },
);

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
      await f.runtime.run((call) => f.first.probe(call));
      await f.runtime.run((call) => f.second.probe(call));
      const empty = await backend.app.sql.query<{ count: number }>('main', {
        text: `SELECT count(*)::integer AS count FROM ${backend.schema}.security_records`,
      });
      assert.equal(empty.rows[0]!.count, 0);
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
