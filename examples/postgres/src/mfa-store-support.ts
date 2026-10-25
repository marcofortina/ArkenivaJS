// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { copyData } from '@arkenivajs/core/support';

/** Fixed diagnostic without subject, session or secret values. */
export const mfaPolicyError = () =>
  new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid MFA storage input' });

/** Bound stored text without interpreting it as an authenticated identity. */
export function mfaText(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length < 1 || value.length > 1024) throw mfaPolicyError();
  for (const character of value)
    if (character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127) throw mfaPolicyError();
}

/** Copy plain data without invoking accessors and reject undeclared metadata. */
export function mfaObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  let owned: unknown;
  try {
    owned = copyData(value);
  } catch {
    throw mfaPolicyError();
  }
  if (!owned || typeof owned !== 'object' || Array.isArray(owned)) throw mfaPolicyError();
  const record = owned as Record<string, unknown>;
  if (Object.keys(record).some((key) => !keys.includes(key))) throw mfaPolicyError();
  return record;
}

/** Accept a real UTC instant, rejecting calendar rollover and ambiguous local times. */
export function mfaInstant(value: unknown): number {
  mfaText(value);
  const parsed = Date.parse(value);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) ||
    !Number.isFinite(parsed) ||
    new Date(parsed).toISOString().slice(0, 19) !== value.slice(0, 19)
  )
    throw mfaPolicyError();
  return parsed;
}

/** Validate an opaque reference-adapter ID without accepting a path or expression. */
export function mfaId(value: unknown): asserts value is string {
  mfaText(value);
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(value)) throw mfaPolicyError();
}

/** Restrict test DDL and queries to a fixed table in a caller-owned random namespace. */
export function mfaTable(
  schema: string,
  suffix:
    'challenges' | 'rate_limits' | 'evidence' | 'totp_accounts' | 'totp_pending' | 'totp_recovery',
): string {
  if (process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MFA storage example requires a disposable PostgreSQL fixture',
    });
  if (
    typeof schema !== 'string' ||
    !/^mfa_[a-f0-9]{24}$/.test(schema) ||
    ![
      'challenges',
      'rate_limits',
      'evidence',
      'totp_accounts',
      'totp_pending',
      'totp_recovery',
    ].includes(suffix)
  )
    throw mfaPolicyError();
  return schema + '.mfa_' + suffix;
}

/** Preserve cooperative cancellation; unavailable or uncertain persistence never grants proof. */
export async function mfaStorage<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (cause) {
    if (cause instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(cause.code)) throw cause;
    throw new KitError({ code: 'EK_MFA_STORAGE', message: 'MFA storage is unavailable', cause });
  }
}
