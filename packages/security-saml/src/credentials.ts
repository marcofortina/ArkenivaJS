// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createPrivateKey, createPublicKey, X509Certificate, timingSafeEqual } from 'node:crypto';
import { types, TextDecoder } from 'node:util';
import type { Settings } from './settings.js';
import type { Call } from './runtime.js';
import { fields, failure, text } from './validation.js';

const prototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const length = Object.getOwnPropertyDescriptor(prototype, 'byteLength')!.get!;
const buffer = Object.getOwnPropertyDescriptor(prototype, 'buffer')!.get!;
const offset = Object.getOwnPropertyDescriptor(prototype, 'byteOffset')!.get!;
async function secret(settings: Settings, reference: string, call: Call): Promise<Buffer> {
  const result = fields(
    await call.step('EK_BACKEND_UNAVAILABLE', (options) =>
      settings.secretProvider.get(reference, options),
    ),
    ['bytes', 'keyVersion', 'expiresAt'],
  );
  text(result.keyVersion, 256);
  if (
    result.expiresAt !== undefined &&
    (typeof result.expiresAt !== 'string' ||
      !Number.isFinite(Date.parse(result.expiresAt)) ||
      Date.parse(result.expiresAt) <= Date.now())
  )
    throw failure();
  if (!types.isUint8Array(result.bytes) || types.isProxy(result.bytes)) throw failure();
  const storage = buffer.call(result.bytes) as ArrayBuffer,
    size = length.call(result.bytes) as number;
  if (!(storage instanceof ArrayBuffer) || size < 1 || size > 32768) throw failure();
  const copy = Buffer.alloc(size);
  Uint8Array.prototype.set.call(
    copy,
    new Uint8Array(storage, offset.call(result.bytes) as number, size),
  );
  return copy;
}
/** Fresh versioned provider reads permit rotation without keeping raw private keys in application state. */
export async function credentials(
  settings: Settings,
  call: Call,
): Promise<{ privateKey?: string; publicCert?: string }> {
  if (!settings.signingKeyRef) return {};
  const key = await secret(settings, settings.signingKeyRef, call);
  let certificate: Buffer | undefined;
  try {
    certificate = await secret(settings, settings.signingCertificateRef!, call);
    const privateKey = createPrivateKey(new TextDecoder('utf-8', { fatal: true }).decode(key)),
      publicCert = new X509Certificate(certificate);
    if (
      privateKey.asymmetricKeyType !== 'rsa' ||
      (privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048 ||
      Date.now() < Date.parse(publicCert.validFrom) ||
      Date.now() >= Date.parse(publicCert.validTo)
    )
      throw failure();
    const expected = publicCert.publicKey.export({ format: 'der', type: 'spki' }),
      actual = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw failure();
    return {
      privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      publicCert: publicCert.toString(),
    };
  } catch {
    throw failure();
  } finally {
    key.fill(0);
    certificate?.fill(0);
  }
}
