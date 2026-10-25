// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { MfaSecretProtector, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { mfaObject, mfaPolicyError, mfaStorage, mfaText } from './mfa-store-support.js';

type Binding = Parameters<MfaSecretProtector['seal']>[1];
type KeyResolver = (keyId: string, options?: OperationOptions) => Promise<Uint8Array>;

function keyIdentifier(value: unknown): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 64 ||
    /[^A-Za-z0-9_-]/.test(value)
  )
    throw mfaPolicyError();
}
function associatedData(binding: Binding, keyId: string): Buffer {
  const record = mfaObject(binding, ['issuer', 'subject', 'tenantId']);
  mfaText(record.issuer);
  mfaText(record.subject);
  if ('tenantId' in record) mfaText(record.tenantId);
  return Buffer.from(
    JSON.stringify([
      'arkenivajs-mfa-secret-v1',
      keyId,
      record.issuer,
      record.subject,
      record.tenantId ?? null,
    ]),
    'utf8',
  );
}
function base64(value: unknown, minimum: number, maximum: number): Buffer {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum / 3) * 4)
    throw mfaPolicyError();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString('base64') !== value)
    throw mfaPolicyError();
  return bytes;
}

/**
 * Disposable application-owned AES-256-GCM reference, not a production key manager.
 * The trusted resolver owns versioned keys; this adapter never exposes or changes them.
 */
export function createDisposableMfaSecretProtector(
  activeKeyId: string,
  resolveKey: KeyResolver,
): MfaSecretProtector {
  if (process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Secret example requires a disposable fixture',
    });
  keyIdentifier(activeKeyId);
  if (typeof resolveKey !== 'function') throw mfaPolicyError();

  const operate = <T>(
    keyId: string,
    input: OperationOptions,
    work: (key: Buffer, check: () => void) => T,
  ): Promise<T> => {
    const options = { ...input };
    const deadline = performance.now() + (options.timeoutMs ?? 30000);
    const check = () => {
      if (options.signal?.aborted)
        throw new KitError({ code: 'EK_ABORTED', message: 'Secret operation aborted' });
      if (performance.now() >= deadline)
        throw new KitError({ code: 'EK_TIMEOUT', message: 'Secret operation timed out' });
    };
    return mfaStorage(() =>
      within(async () => {
        check();
        const provided = await resolveKey(keyId, options);
        let key: Buffer | undefined;
        try {
          check();
          if (!(provided instanceof Uint8Array) || provided.byteLength !== 32)
            throw mfaPolicyError();
          key = Buffer.from(provided);
          return work(key, check);
        } finally {
          key?.fill(0);
        }
      }, options),
    );
  };

  return Object.freeze<MfaSecretProtector>({
    async seal(plain, binding, options = {}) {
      if (!(plain instanceof Uint8Array) || plain.byteLength < 1 || plain.byteLength > 4096)
        throw mfaPolicyError();
      const aad = associatedData(binding, activeKeyId),
        owned = Buffer.from(plain);
      try {
        return await operate(activeKeyId, options, (key, check) => {
          const nonce = randomBytes(12),
            cipher = createCipheriv('aes-256-gcm', key, nonce);
          cipher.setAAD(aad);
          const ciphertext = Buffer.concat([cipher.update(owned), cipher.final()]);
          check();
          return Object.freeze({
            keyId: activeKeyId,
            ciphertext: ciphertext.toString('base64'),
            nonce: nonce.toString('base64'),
            tag: cipher.getAuthTag().toString('base64'),
          });
        });
      } finally {
        owned.fill(0);
      }
    },
    async open(secret, binding, options = {}) {
      const record = mfaObject(secret, ['keyId', 'ciphertext', 'nonce', 'tag']);
      keyIdentifier(record.keyId);
      const keyId = record.keyId,
        aad = associatedData(binding, keyId);
      const ciphertext = base64(record.ciphertext, 1, 4096),
        nonce = base64(record.nonce, 12, 12),
        tag = base64(record.tag, 16, 16);
      return operate(keyId, options, (key, check) => {
        const decipher = createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);
        const pending = decipher.update(ciphertext);
        let final: Buffer | undefined;
        try {
          final = decipher.final();
          check();
          const result = new Uint8Array(pending.length + final.length);
          result.set(pending);
          result.set(final, pending.length);
          return result;
        } finally {
          pending.fill(0);
          final?.fill(0);
        }
      });
    },
  });
}
