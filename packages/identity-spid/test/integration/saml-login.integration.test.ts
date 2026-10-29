// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  securityStateFixture,
  independentSecurityStatePeer,
} from '../../../../examples/postgres/dist-test/integration/security-state-fixture.js';
import { samlLoginFixture } from '../fixtures/saml-login.js';
import { closeRegistryFixture } from '../fixtures/saml-metadata.js';
import { FederationTransactions } from '../../dist/transactions.js';

after(closeRegistryFixture);

test(
  'Native signed SPID login persists private correlation and has one winner through separate PostgreSQL pools',
  { timeout: 30000 },
  async () => {
    const backend = await securityStateFixture(),
      peer = await independentSecurityStatePeer(backend.schema),
      f = await samlLoginFixture({
        store: backend.store,
        securityLevel: 'test-only',
        operationTimeoutMs: 5000,
      });
    try {
      assert.notEqual(peer.app, backend.app);
      assert.notEqual(peer.app.sql, backend.app.sql);
      const login = await f.runtime.run((call) => f.login.begin(call, f.input)),
        requestId = new URL(login.redirectUrl).searchParams.get('RelayState')!,
        rows = await peer.app.sql.query<{ namespace: string; body: string }>('main', {
          text: `SELECT namespace,body FROM ${backend.schema}.security_records`,
        }),
        encrypted = rows.rows.find((row) => row.namespace === 'arkenivajs.spid.authorization.v1')!,
        native = rows.rows.map((row) => JSON.parse(row.body)).find((row) => row.kind === 'login');
      assert.ok(encrypted);
      assert.equal(native.returnPath, '/');
      assert.equal(native.id, requestId);
      for (const value of [requestId, login.transactionId, f.input.returnPath, f.input.tenantHint])
        assert.equal(encrypted.body.includes(value), false);
      const other = new FederationTransactions(
          { ...f.settings, stateStore: { ...f.settings.stateStore, store: peer.store } },
          f.document.profile.profileId,
          f.crypto,
        ),
        outcomes = await Promise.allSettled(
          Array.from({ length: 8 }, (_, index) =>
            f.runtime.run((call) =>
              (index % 2 ? other : f.transactions).consume(
                call,
                login.transactionId,
                f.document.issuer,
              ),
            ),
          ),
        ),
        winners = outcomes.filter((result) => result.status === 'fulfilled');
      assert.equal(winners.length, 1);
      assert.equal(winners[0]!.value.samlRequestId, requestId);
      assert.equal(winners[0]!.value.tenantHint, f.input.tenantHint);
      await assert.rejects(
        () => f.runtime.run((call) => other.consume(call, login.transactionId, f.document.issuer)),
        { code: 'EK_EID_FEDERATION' },
      );
    } finally {
      await f.close();
      await peer.close();
      await backend.close();
    }
  },
);
