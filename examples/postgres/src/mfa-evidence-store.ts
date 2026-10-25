// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  MfaEvidenceRecord,
  MfaEvidenceStore,
  OperationOptions,
  SqlProvider,
} from '@arkenivajs/core';
import {
  mfaId,
  mfaInstant,
  mfaObject,
  mfaPolicyError,
  mfaStorage,
  mfaTable,
  mfaText,
} from './mfa-store-support.js';

function evidence(value: unknown): MfaEvidenceRecord {
  const record = mfaObject(value, [
    'evidenceId',
    'method',
    'assurance',
    'subject',
    'verifiedAt',
    'expiresAt',
    'issuer',
    'tenantId',
    'primarySessionId',
  ]);
  mfaId(record.evidenceId);
  for (const key of ['issuer', 'subject', 'primarySessionId']) mfaText(record[key]);
  if (Object.hasOwn(record, 'tenantId')) mfaText(record.tenantId);
  if (
    typeof record.method !== 'string' ||
    !['totp', 'recovery-code', 'webauthn'].includes(record.method) ||
    typeof record.assurance !== 'string' ||
    !['single-factor', 'mfa', 'phishing-resistant'].includes(record.assurance) ||
    (record.method !== 'webauthn' && record.assurance === 'phishing-resistant') ||
    mfaInstant(record.expiresAt) <= mfaInstant(record.verifiedAt)
  )
    throw mfaPolicyError();
  return Object.freeze(record) as unknown as MfaEvidenceRecord;
}

/** Create the evidence table in an owned disposable schema; consumed records remain as replay tombstones. */
export async function createPostgresMfaEvidenceTable(
  sql: SqlProvider,
  connection: string,
  schema: string,
): Promise<void> {
  const name = mfaTable(schema, 'evidence');
  mfaText(connection);
  await mfaStorage(() =>
    sql.execute(connection, {
      text: `CREATE TABLE ${name} (
      id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
      tenant_id TEXT, primary_session_id TEXT NOT NULL,
      method TEXT NOT NULL, assurance TEXT NOT NULL,
      verified_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
      consumed_at TIMESTAMPTZ, body JSONB NOT NULL
    )`,
    }),
  );
}

/**
 * Durable server-side handoff reference, not a factor verifier or session issuer.
 * Only trusted verification code may record evidence; the session authority must
 * consume for the exact authenticated owner before upgrading its own session.
 */
export function createPostgresMfaEvidenceStore(
  sql: SqlProvider,
  connection: string,
  schema: string,
): MfaEvidenceStore {
  const name = mfaTable(schema, 'evidence');
  mfaText(connection);
  return Object.freeze({
    async recordOnce(input: MfaEvidenceRecord, options?: OperationOptions): Promise<void> {
      const record = evidence(input);
      await mfaStorage(() =>
        sql.execute(
          connection,
          {
            text: `INSERT INTO ${name} (id,issuer,subject,tenant_id,primary_session_id,method,assurance,verified_at,expires_at,body)
          VALUES (:id,:issuer,:subject,:tenant,:session,:method,:assurance,:verified::timestamptz,:expires::timestamptz,:body::jsonb)`,
            bindings: {
              id: record.evidenceId,
              issuer: record.issuer,
              subject: record.subject,
              tenant: record.tenantId ?? null,
              session: record.primarySessionId,
              method: record.method,
              assurance: record.assurance,
              verified: record.verifiedAt,
              expires: record.expiresAt,
              body: JSON.stringify(record),
            },
          },
          options,
        ),
      );
    },
    async consume(
      input: Parameters<MfaEvidenceStore['consume']>[0],
      options?: OperationOptions,
    ): Promise<MfaEvidenceRecord | null> {
      const claim = mfaObject(input, [
        'evidenceId',
        'issuer',
        'subject',
        'tenantId',
        'primarySessionId',
        'now',
      ]);
      mfaId(claim.evidenceId);
      for (const key of ['issuer', 'subject', 'primarySessionId']) mfaText(claim[key]);
      if (Object.hasOwn(claim, 'tenantId')) mfaText(claim.tenantId);
      mfaInstant(claim.now);
      const row = await mfaStorage(() =>
        sql.queryOne<{
          body: string;
          method: string;
          assurance: string;
          verified_match: boolean;
          expires_match: boolean;
        }>(
          connection,
          {
            // Retaining the primary-key tombstone also blocks re-recording after a successful consume.
            text: `UPDATE ${name} SET consumed_at=:now::timestamptz
          WHERE id=:id AND issuer=:issuer AND subject=:subject
            AND tenant_id IS NOT DISTINCT FROM :tenant AND primary_session_id=:session
            AND consumed_at IS NULL AND verified_at <= :now::timestamptz
            AND expires_at > :now::timestamptz
          RETURNING body,method,assurance,
            (body->>'verifiedAt')::timestamptz=verified_at AS verified_match,
            (body->>'expiresAt')::timestamptz=expires_at AS expires_match`,
            bindings: {
              id: String(claim.evidenceId),
              issuer: String(claim.issuer),
              subject: String(claim.subject),
              tenant: claim.tenantId === undefined ? null : String(claim.tenantId),
              session: String(claim.primarySessionId),
              now: String(claim.now),
            },
          },
          options,
        ),
      );
      if (!row) return null;
      return mfaStorage(async () => {
        if (typeof row.body !== 'string' || row.body.length > 16384) throw mfaPolicyError();
        const consumed = evidence(JSON.parse(row.body));
        if (
          consumed.method !== row.method ||
          consumed.assurance !== row.assurance ||
          row.verified_match !== true ||
          row.expires_match !== true
        )
          throw mfaPolicyError();
        for (const key of [
          'evidenceId',
          'issuer',
          'subject',
          'tenantId',
          'primarySessionId',
        ] as const)
          if (consumed[key] !== claim[key]) throw mfaPolicyError();
        if (
          mfaInstant(consumed.verifiedAt) > mfaInstant(claim.now) ||
          mfaInstant(consumed.expiresAt) <= mfaInstant(claim.now)
        )
          throw mfaPolicyError();
        return consumed;
      });
    },
  });
}
