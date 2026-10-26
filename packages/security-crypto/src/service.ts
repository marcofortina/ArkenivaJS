// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { CryptoService } from './contracts.js';
import { bytes, createRuntime, data, failure, format, text } from './runtime.js';
import type { Settings } from './runtime.js';

/** Bind envelope metadata and caller AAD using an unambiguous native GCM AAD input. */
function binding(keyId: string, aad: Uint8Array): Buffer {
  const header = Buffer.from(JSON.stringify([1, 'AES-256-GCM', keyId]));
  const lengths = Buffer.alloc(8);
  lengths.writeUInt32BE(header.length);
  lengths.writeUInt32BE(aad.length, 4);
  return Buffer.concat([lengths, header, aad]);
}
function algorithm(key: KeyObject): null | 'sha256' {
  if (key.asymmetricKeyType === 'ed25519') return null;
  if (key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1')
    return 'sha256';
  throw format();
}
export function createService(settings: Settings) {
  const runtime = createRuntime(settings);
  function limit(size: number, maximum = settings.maxOutputBytes) {
    if (size > maximum) throw format();
  }
  const service = Object.freeze<CryptoService>({
    encrypt(plaintext, keyRef, aad, options) {
      return runtime.run(options, async (call) => {
        const input = bytes(plaintext, settings.maxInputBytes);
        let context: Buffer | undefined,
          authenticated: Buffer | undefined,
          material: Buffer | undefined;
        try {
          context =
            aad === undefined ? Buffer.alloc(0) : bytes(aad, settings.maxInputBytes - input.length);
          limit(input.length + 28);
          const key = await runtime.key(keyRef, settings.encryption, call, 32);
          material = key.material;
          authenticated = binding(key.version, context);
          const nonce = randomBytes(12),
            cipher = createCipheriv('aes-256-gcm', material, nonce, { authTagLength: 16 });
          cipher.setAAD(authenticated);
          const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
          return Object.freeze({
            version: 1,
            algorithm: 'AES-256-GCM',
            keyId: key.version,
            nonce,
            ciphertext,
            tag: cipher.getAuthTag(),
          });
        } finally {
          input.fill(0);
          context?.fill(0);
          authenticated?.fill(0);
          material?.fill(0);
        }
      });
    },
    decrypt(envelope, keyRef, aad, options) {
      return runtime.run(options, async (call) => {
        const value = data(envelope, [
          'version',
          'algorithm',
          'keyId',
          'nonce',
          'ciphertext',
          'tag',
        ]);
        if (value.version !== 1 || value.algorithm !== 'AES-256-GCM') throw format();
        text(value.keyId);
        const owned: Buffer[] = [];
        const copy = (value: unknown, maximum: number, exact?: number) => {
          const result = bytes(value, maximum, exact);
          owned.push(result);
          return result;
        };
        let material: Buffer | undefined, partial: Buffer | undefined;
        try {
          const ciphertext = copy(value.ciphertext, settings.maxInputBytes),
            nonce = copy(value.nonce, 12, 12),
            tag = copy(value.tag, 16, 16);
          const context =
            aad === undefined
              ? Buffer.alloc(0)
              : copy(aad, settings.maxInputBytes - ciphertext.length);
          limit(ciphertext.length);
          const key = await runtime.key(keyRef, settings.encryption, call, 32);
          material = key.material;
          if (key.version !== value.keyId) throw failure('EK_CRYPTO_KEY_UNAVAILABLE');
          const authenticated = binding(key.version, context);
          owned.push(authenticated);
          const decipher = createDecipheriv('aes-256-gcm', material, nonce, { authTagLength: 16 });
          decipher.setAAD(authenticated);
          decipher.setAuthTag(tag);
          try {
            partial = decipher.update(ciphertext);
            return Buffer.concat([partial, decipher.final()]);
          } catch {
            throw failure('EK_CRYPTO_AUTH_FAILED');
          }
        } finally {
          for (const item of owned) item.fill(0);
          material?.fill(0);
          partial?.fill(0);
        }
      });
    },
    hmac(input, keyRef, options) {
      return runtime.run(options, async (call) => {
        const snapshot = bytes(input, settings.maxInputBytes);
        let material: Buffer | undefined;
        try {
          limit(32);
          const key = await runtime.key(keyRef, settings.signing, call);
          material = key.material;
          return createHmac('sha256', material).update(snapshot).digest();
        } finally {
          snapshot.fill(0);
          material?.fill(0);
        }
      });
    },
    verifyMac(input, mac, keyRef, options) {
      return runtime.run(options, async (call) => {
        const snapshot = bytes(input, settings.maxInputBytes);
        let expected: Buffer | undefined, actual: Buffer | undefined, material: Buffer | undefined;
        try {
          expected = bytes(mac, 32, 32);
          const key = await runtime.key(keyRef, settings.signing, call);
          material = key.material;
          actual = createHmac('sha256', material).update(snapshot).digest();
          return timingSafeEqual(actual, expected);
        } finally {
          snapshot.fill(0);
          expected?.fill(0);
          actual?.fill(0);
          material?.fill(0);
        }
      });
    },
    sign(input, keyRef, options) {
      return runtime.run(options, async (call) => {
        const snapshot = bytes(input, settings.maxInputBytes);
        let material: Buffer | undefined;
        try {
          limit(64);
          const secret = await runtime.key(keyRef, settings.signing, call);
          material = secret.material;
          let key: KeyObject;
          try {
            key = createPrivateKey({ key: material, format: 'der', type: 'pkcs8' });
          } catch {
            throw format();
          }
          return sign(algorithm(key), snapshot, { key, dsaEncoding: 'ieee-p1363' });
        } finally {
          snapshot.fill(0);
          material?.fill(0);
        }
      });
    },
    verifySignature(input, signature, publicKey, options) {
      return runtime.run(options, async () => {
        const snapshot = bytes(input, settings.maxInputBytes);
        let supplied: Buffer | undefined, spki: Buffer | undefined;
        try {
          supplied = bytes(signature, 64, 64);
          spki = bytes(publicKey, 16384);
          let key: KeyObject;
          try {
            key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
          } catch {
            throw format();
          }
          return verify(algorithm(key), snapshot, { key, dsaEncoding: 'ieee-p1363' }, supplied);
        } finally {
          snapshot.fill(0);
          supplied?.fill(0);
          spki?.fill(0);
        }
      });
    },
  });
  return { service, bootstrap: runtime.bootstrap, close: runtime.close };
}
