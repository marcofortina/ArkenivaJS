// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { MfaEvidenceRecord, SqlProvider } from '@arkenivajs/core';
import { createPostgresMfaEvidenceStore } from '../../dist/mfa-evidence-store.js';

const evidence: MfaEvidenceRecord = {
  evidenceId: 'synthetic-evidence',
  method: 'totp',
  assurance: 'mfa',
  issuer: 'https://issuer.example.test',
  subject: 'synthetic-account',
  tenantId: 'tenant-a',
  primarySessionId: 'session-a',
  verifiedAt: '2026-10-25T00:00:00.000Z',
  expiresAt: '2026-10-25T00:01:00.000Z',
};
test('Evidence storage rejects raw proof, missing ownership and impossible factor assurance before SQL', async (t) => {
  const before = process.env.ARKENIVA_POSTGRES_DISPOSABLE;
  process.env.ARKENIVA_POSTGRES_DISPOSABLE = '1';
  t.after(() => {
    if (before === undefined) delete process.env.ARKENIVA_POSTGRES_DISPOSABLE;
    else process.env.ARKENIVA_POSTGRES_DISPOSABLE = before;
  });
  let calls = 0;
  const fail = async () => {
    calls++;
    throw new Error('SQL must not run');
  };
  const sql: SqlProvider = {
    query: fail,
    queryOne: fail,
    execute: fail,
    transaction: fail,
    ping: fail,
    stats: () => ({}),
    native: () => undefined,
  };
  const store = createPostgresMfaEvidenceStore(sql, 'main', 'mfa_' + 'a'.repeat(24));
  for (const change of [
    { method: 'unknown' },
    { method: 'totp', assurance: 'phishing-resistant' },
    { method: 'recovery-code', assurance: 'phishing-resistant' },
    { primarySessionId: '' },
    { issuer: undefined },
    { tenantId: undefined },
    { expiresAt: evidence.verifiedAt },
    { otp: 'synthetic-proof' },
  ])
    await assert.rejects(
      store.recordOnce({ ...evidence, ...change } as MfaEvidenceRecord),
      (error) => error instanceof KitError && error.code === 'EK_MFA_POLICY',
    );
  assert.equal(calls, 0);
  await assert.rejects(
    store.recordOnce(evidence),
    (error) => error instanceof KitError && error.code === 'EK_MFA_STORAGE',
  );
  assert.equal(calls, 1);
});
