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
import { FederationSamlLogin } from '../../dist/saml-login.js';
import { samlResponse } from '../fixtures/saml-response.js';

after(closeRegistryFixture);

for (const level of [2, 3])
  test(
    `Actual signed SPID SAML level ${level} callback has one identity winner across independent PostgreSQL pools`,
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
        const settings = {
            ...f.settings,
            profiles: [
              { ...f.document.profile, allowedAssurance: ['spid-l2', 'spid-l3'] as const },
            ],
          },
          first = new FederationSamlLogin(
            settings,
            f.document.profile.profileId,
            f.transport,
            f.crypto,
          ),
          other = new FederationSamlLogin(
            { ...settings, stateStore: { ...f.settings.stateStore, store: peer.store } },
            f.document.profile.profileId,
            f.transport,
            f.crypto,
          ),
          login = await f.runtime.run((call) => first.begin(call, f.input)),
          response = samlResponse(f, login, { context: 'https://www.spid.gov.it/SpidL' + level }),
          outcomes = await Promise.allSettled(
            Array.from({ length: 8 }, (_, index) =>
              f.runtime.run((call) => (index % 2 ? other : first).consume(call, response)),
            ),
          ),
          winners = outcomes.filter((result) => result.status === 'fulfilled');
        assert.equal(winners.length, 1);
        assert.equal(winners[0]!.value.returnPath, f.input.returnPath);
        assert.equal(winners[0]!.value.tenantHint, f.input.tenantHint);
        assert.equal(winners[0]!.value.subject, 'synthetic-transient-subject');
        assert.equal(winners[0]!.value.assurance, 'spid-l' + level);
        await assert.rejects(() => f.runtime.run((call) => other.consume(call, response)), {
          code: 'EK_EID_FEDERATION',
        });
        const persisted = await peer.app.sql.query<{ count: number }>('main', {
          text: `SELECT count(*)::integer AS count FROM ${backend.schema}.security_records WHERE namespace LIKE :kind`,
          bindings: { kind: '%:sessions' },
        });
        assert.equal(persisted.rows[0]!.count, 1);
      } finally {
        await f.close();
        await peer.close();
        await backend.close();
      }
    },
  );

test(
  'A lost actual PostgreSQL SAML session acknowledgement returns no identity and denies retry',
  { timeout: 30000 },
  async () => {
    const backend = await securityStateFixture();
    let writes = 0;
    const f = await samlLoginFixture({
      store: {
        ...backend.store,
        async compareAndSet(...args) {
          const receipt = await backend.store.compareAndSet(...args);
          if (args[0].endsWith(':sessions') && receipt.committed) {
            writes++;
            throw new Error('The disposable session acknowledgement was lost');
          }
          return receipt;
        },
      },
      securityLevel: 'test-only',
      operationTimeoutMs: 5000,
    });
    try {
      const login = await f.runtime.run((call) => f.login.begin(call, f.input)),
        response = samlResponse(f, login);
      await assert.rejects(() => f.runtime.run((call) => f.login.consume(call, response)), {
        code: 'EK_BACKEND_UNAVAILABLE',
      });
      assert.equal(writes, 1);
      await assert.rejects(() => f.runtime.run((call) => f.login.consume(call, response)), {
        code: 'EK_EID_FEDERATION',
      });
      const persisted = await backend.app.sql.query<{ count: number }>('main', {
        text: `SELECT count(*)::integer AS count FROM ${backend.schema}.security_records WHERE namespace LIKE :kind`,
        bindings: { kind: '%:sessions' },
      });
      assert.equal(persisted.rows[0]!.count, 1);
    } finally {
      await f.close();
      await backend.close();
    }
  },
);

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
