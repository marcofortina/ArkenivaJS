// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { MfaRateLimitStore, OperationOptions, SqlProvider } from '@arkenivajs/core';
import { createHash } from 'node:crypto';
import { mfaObject, mfaPolicyError, mfaStorage, mfaTable, mfaText } from './mfa-store-support.js';

function integer(value: unknown, minimum: number): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum)
    throw mfaPolicyError();
}
function persisted(value: unknown): bigint {
  if (typeof value !== 'string' || !/^\d{1,16}$/.test(value)) throw mfaPolicyError();
  const result = BigInt(value);
  if (result > BigInt(Number.MAX_SAFE_INTEGER)) throw mfaPolicyError();
  return result;
}

/** Create the atomic limiter table only in an explicitly disposable, already-owned schema. */
export async function createPostgresMfaRateLimitTable(
  sql: SqlProvider,
  connection: string,
  schema: string,
): Promise<void> {
  const name = mfaTable(schema, 'rate_limits');
  mfaText(connection);
  await mfaStorage(() =>
    sql.execute(connection, {
      text: `CREATE TABLE ${name} (
      bucket_id TEXT PRIMARY KEY,
      window_started_ms BIGINT NOT NULL, window_ms BIGINT NOT NULL,
      attempts BIGINT NOT NULL, capacity BIGINT NOT NULL
    )`,
    }),
  );
}

/** Application-owned fixed-window reference: one atomic transition, shared across Node processes. */
export function createPostgresMfaRateLimitStore(
  sql: SqlProvider,
  connection: string,
  schema: string,
): MfaRateLimitStore {
  const name = mfaTable(schema, 'rate_limits');
  mfaText(connection);
  return Object.freeze({
    async checkAndRecord(
      input: Parameters<MfaRateLimitStore['checkAndRecord']>[0],
      options?: OperationOptions,
    ) {
      const value = mfaObject(input, ['scopeKey', 'operation', 'maxAttempts', 'windowMs', 'nowMs']);
      mfaText(value.scopeKey);
      mfaText(value.operation);
      integer(value.maxAttempts, 1);
      integer(value.windowMs, 1);
      integer(value.nowMs, 0);
      if (
        !Number.isSafeInteger(value.maxAttempts + 1) ||
        !Number.isSafeInteger(value.nowMs + value.windowMs)
      )
        throw mfaPolicyError();
      // Fixed-width framed hashes avoid index-size failures and do not persist raw account scope keys.
      const bucket = createHash('sha256')
        .update(JSON.stringify(['arkenivajs-mfa-limit-v1', value.scopeKey, value.operation]))
        .digest('hex');
      const row = await mfaStorage(() =>
        sql.queryOne<{
          attempts: string;
          capacity: string;
          window_ms: string;
          window_started_ms: string;
        }>(
          connection,
          {
            text: `INSERT INTO ${name} AS limiter
          (bucket_id,window_started_ms,window_ms,attempts,capacity)
          VALUES (:bucket,:now,:window,1,:capacity)
          ON CONFLICT(bucket_id) DO UPDATE SET
            window_started_ms=CASE WHEN :now >= limiter.window_started_ms+limiter.window_ms THEN :now ELSE limiter.window_started_ms END,
            attempts=CASE WHEN :now >= limiter.window_started_ms+limiter.window_ms THEN 1 WHEN :now < limiter.window_started_ms THEN limiter.capacity+1 ELSE LEAST(limiter.attempts+1,limiter.capacity+1) END,
            capacity=EXCLUDED.capacity, window_ms=EXCLUDED.window_ms
          WHERE (limiter.capacity=EXCLUDED.capacity AND limiter.window_ms=EXCLUDED.window_ms)
             OR :now >= limiter.window_started_ms+limiter.window_ms
          RETURNING attempts,capacity,window_ms,window_started_ms`,
            bindings: {
              bucket,
              now: value.nowMs as number,
              window: value.windowMs as number,
              capacity: value.maxAttempts as number,
            },
          },
          options,
        ),
      );
      // A policy disagreement during an active window is a configuration error, never a quota reset.
      if (!row) throw mfaPolicyError();
      return mfaStorage(async () => {
        const attempts = persisted(row.attempts),
          capacity = persisted(row.capacity);
        const window = persisted(row.window_ms),
          started = persisted(row.window_started_ms);
        const now = BigInt(value.nowMs as number);
        if (
          capacity !== BigInt(value.maxAttempts as number) ||
          window !== BigInt(value.windowMs as number) ||
          attempts < 1n ||
          attempts > capacity + 1n ||
          started + window > BigInt(Number.MAX_SAFE_INTEGER)
        )
          throw mfaPolicyError();
        // A backward clock jump retains the current bucket and denies until its original end.
        if (now >= started && attempts <= capacity) return { allowed: true };
        const remaining = started + window - now;
        if (remaining < 1n || remaining > BigInt(Number.MAX_SAFE_INTEGER)) throw mfaPolicyError();
        return { allowed: false, retryAfterMs: Number(remaining) };
      });
    },
  });
}
