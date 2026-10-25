// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHmac } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import type { TotpRecoveryHmacProvider, TotpRecoveryProofInput } from '@arkenivajs/security-totp';
import { copyData, within } from '@arkenivajs/core/support';

type KeySnapshot = { readonly current: string; readonly allowed: readonly string[] };
const unavailable = () =>
  new KitError({ code: 'EK_MFA_STORAGE', message: 'Recovery protection is unavailable' });

/** Disposable application-owned reference. Production deployments need an independently reviewed secret/KMS backend. */
export function createDisposableRecoveryHmacProvider(
  snapshot: (options?: OperationOptions) => Promise<KeySnapshot>,
  resolveKey: (version: string, options?: OperationOptions) => Promise<Uint8Array>,
): TotpRecoveryHmacProvider {
  if (
    process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1' ||
    typeof snapshot !== 'function' ||
    typeof resolveKey !== 'function'
  )
    throw new KitError({
      code: 'EK_MFA_POLICY',
      message: 'Disposable recovery protection requires explicit opt-in',
    });
  const versions = async (options?: OperationOptions) => {
    const supplied = await snapshot(options);
    if (!supplied || typeof supplied !== 'object') throw unavailable();
    const currentField = Object.getOwnPropertyDescriptor(supplied, 'current'),
      allowedField = Object.getOwnPropertyDescriptor(supplied, 'allowed');
    if (!currentField || !('value' in currentField) || !allowedField || !('value' in allowedField))
      throw unavailable();
    const current: unknown = currentField.value,
      raw: unknown = allowedField.value;
    if (!Array.isArray(raw)) throw unavailable();
    const length = raw.length;
    if (!Number.isSafeInteger(length) || length < 1 || length > 8) throw unavailable();
    const allowed: string[] = [];
    for (let index = 0; index < length; index++) {
      const field = Object.getOwnPropertyDescriptor(raw, String(index));
      if (
        !field ||
        !('value' in field) ||
        typeof field.value !== 'string' ||
        !/^[A-Za-z0-9_-]{1,64}$/.test(field.value)
      )
        throw unavailable();
      allowed.push(field.value);
    }
    if (
      typeof current !== 'string' ||
      !allowed.includes(current) ||
      new Set(allowed).size !== length
    )
      throw unavailable();
    return Object.freeze({ current, allowed: Object.freeze(allowed) });
  };

  const mac = async (
    version: string,
    input: TotpRecoveryProofInput,
    options?: OperationOptions,
  ) => {
    const proof = copyData(input);
    for (const value of [proof.issuer, proof.subject, proof.factorId, proof.code])
      if (
        typeof value !== 'string' ||
        value.length < 1 ||
        value.length > 1024 ||
        [...value].some(
          (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
        )
      )
        throw unavailable();
    if (
      proof.tenantId !== undefined &&
      (typeof proof.tenantId !== 'string' || !proof.tenantId || proof.tenantId.length > 128)
    )
      throw unavailable();
    const provided = await resolveKey(version, options);
    if (!(provided instanceof Uint8Array) || provided.byteLength < 32 || provided.byteLength > 64)
      throw unavailable();
    const owned = Buffer.from(provided);
    try {
      const digest = createHmac('sha256', owned)
        .update(
          JSON.stringify([
            'v1',
            'arkenivajs-totp-recovery',
            version,
            proof.issuer,
            proof.tenantId ?? null,
            proof.subject,
            proof.factorId,
            proof.code,
          ]),
        )
        .digest('hex');
      return 'v1:' + version + ':' + digest;
    } finally {
      owned.fill(0);
    }
  };
  const protectedCall = async <T>(work: () => Promise<T>, options?: OperationOptions) => {
    try {
      return await within(work, options);
    } catch (error) {
      if (error instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(error.code))
        throw new KitError({ code: error.code, message: 'Recovery protection interrupted' });
      throw unavailable();
    }
  };
  return Object.freeze<TotpRecoveryHmacProvider>({
    algorithm: 'HMAC-SHA256',
    securityLevel: 'test-only',
    createVerifier(input, options) {
      return protectedCall(
        async () => mac((await versions(options)).current, input, options),
        options,
      );
    },
    candidateVerifiers(input, options) {
      return protectedCall(async () => {
        const keys = await versions(options),
          result: string[] = [];
        for (const version of keys.allowed) result.push(await mac(version, input, options));
        return Object.freeze(result);
      }, options);
    },
  });
}
