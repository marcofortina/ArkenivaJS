// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { CRYPTO_CAPABILITY, cryptoPlugin } from '@arkenivajs/security-crypto';
import type {
  CryptoService,
  CryptoPluginSettings,
  SecretProvider,
  SealedEnvelope,
} from '@arkenivajs/security-crypto';
import type { Application, Plugin } from '@arkenivajs/core';

function contract(
  app: Application,
  settings: CryptoPluginSettings,
  secrets: SecretProvider,
  input: Uint8Array,
  envelope: SealedEnvelope,
) {
  const key: symbol = CRYPTO_CAPABILITY;
  const plugin: Plugin = cryptoPlugin(settings);
  const service = app.resolve<CryptoService>(key);
  const encrypted: Promise<SealedEnvelope> = service.encrypt(input, 'approved-key', input, {
    timeoutMs: 1,
  });
  const decrypted: Promise<Uint8Array> = service.decrypt(envelope, 'approved-key');
  const mac: Promise<Uint8Array> = service.hmac(input, 'approved-key');
  const signature: Promise<Uint8Array> = service.sign(input, 'approved-key');
  const validMac: Promise<boolean> = service.verifyMac(input, input, 'approved-key');
  const validSignature: Promise<boolean> = service.verifySignature(input, input, input);
  // @ts-expect-error Raw bytes cannot replace an approved secret reference.
  service.encrypt(input, input);
  // @ts-expect-error The public provider returns versioned opaque bytes, never a raw string.
  const invalidProvider: SecretProvider = { get: async () => 'raw-secret' };
  // @ts-expect-error Configuration requires the explicit bounded runtime policy.
  cryptoPlugin({ secrets, signingKeyRefs: [], encryptionKeyRefs: ['key'] });
  // @ts-expect-error AES algorithms cannot be selected through operation options.
  service.encrypt(input, 'key', input, { algorithm: 'aes-cbc' });
  // @ts-expect-error Envelope versions are governed by the public contract.
  const invalidEnvelope: SealedEnvelope = { ...envelope, version: 2 };
  return {
    plugin,
    encrypted,
    decrypted,
    mac,
    signature,
    validMac,
    validSignature,
    invalidProvider,
    invalidEnvelope,
  };
}
void contract;
