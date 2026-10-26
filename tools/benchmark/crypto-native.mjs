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

function binding(keyId, aad) {
  const header = Buffer.from(JSON.stringify([1, 'AES-256-GCM', keyId])),
    lengths = Buffer.alloc(8);
  lengths.writeUInt32BE(header.length);
  lengths.writeUInt32BE(aad.length, 4);
  return Buffer.concat([lengths, header, aad]);
}

/** Direct native operations over validated benchmark fixtures; no framework lifecycle or admission emulation. */
export function nativeCryptoOperations(provider, fixture) {
  async function withKey(reference, work) {
    const secret = await provider.get(reference),
      material = Buffer.from(secret.bytes);
    try {
      return work(material, secret.keyVersion);
    } finally {
      material.fill(0);
    }
  }
  return {
    async encrypt() {
      const plaintext = Buffer.from(fixture.input),
        aad = Buffer.from(fixture.aad);
      try {
        return await withKey('encryption', (key, keyId) => {
          const nonce = randomBytes(12),
            authenticated = binding(keyId, aad);
          try {
            const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
            cipher.setAAD(authenticated);
            return {
              version: 1,
              algorithm: 'AES-256-GCM',
              keyId,
              nonce,
              ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]),
              tag: cipher.getAuthTag(),
            };
          } finally {
            authenticated.fill(0);
          }
        });
      } finally {
        plaintext.fill(0);
        aad.fill(0);
      }
    },
    async decrypt() {
      const ciphertext = Buffer.from(fixture.envelope.ciphertext),
        nonce = Buffer.from(fixture.envelope.nonce),
        tag = Buffer.from(fixture.envelope.tag),
        aad = Buffer.from(fixture.aad);
      let partial;
      try {
        return await withKey('encryption', (key, keyId) => {
          if (keyId !== fixture.envelope.keyId) throw new Error('Native fixture version mismatch');
          const authenticated = binding(keyId, aad);
          try {
            const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
            decipher.setAAD(authenticated);
            decipher.setAuthTag(tag);
            partial = decipher.update(ciphertext);
            return Buffer.concat([partial, decipher.final()]);
          } finally {
            authenticated.fill(0);
          }
        });
      } finally {
        ciphertext.fill(0);
        nonce.fill(0);
        tag.fill(0);
        aad.fill(0);
        partial?.fill(0);
      }
    },
    async hmac() {
      const input = Buffer.from(fixture.input);
      try {
        return await withKey('hmac', (key) => createHmac('sha256', key).update(input).digest());
      } finally {
        input.fill(0);
      }
    },
    async verifyMac() {
      const input = Buffer.from(fixture.input),
        supplied = Buffer.from(fixture.mac);
      let actual;
      try {
        return await withKey('hmac', (key) => {
          actual = createHmac('sha256', key).update(input).digest();
          return timingSafeEqual(actual, supplied);
        });
      } finally {
        input.fill(0);
        supplied.fill(0);
        actual?.fill(0);
      }
    },
    async signEd25519() {
      const input = Buffer.from(fixture.input);
      try {
        return await withKey('ed', (key) =>
          sign(null, input, {
            key: createPrivateKey({ key, format: 'der', type: 'pkcs8' }),
            dsaEncoding: 'ieee-p1363',
          }),
        );
      } finally {
        input.fill(0);
      }
    },
    async verifyEd25519() {
      const input = Buffer.from(fixture.input),
        signature = Buffer.from(fixture.edSignature),
        spki = Buffer.from(fixture.edPublicKey);
      try {
        return verify(
          null,
          input,
          {
            key: createPublicKey({ key: spki, format: 'der', type: 'spki' }),
            dsaEncoding: 'ieee-p1363',
          },
          signature,
        );
      } finally {
        input.fill(0);
        signature.fill(0);
        spki.fill(0);
      }
    },
    async signP256() {
      const input = Buffer.from(fixture.input);
      try {
        return await withKey('ec', (key) =>
          sign('sha256', input, {
            key: createPrivateKey({ key, format: 'der', type: 'pkcs8' }),
            dsaEncoding: 'ieee-p1363',
          }),
        );
      } finally {
        input.fill(0);
      }
    },
    async verifyP256() {
      const input = Buffer.from(fixture.input),
        signature = Buffer.from(fixture.ecSignature),
        spki = Buffer.from(fixture.ecPublicKey);
      try {
        return verify(
          'sha256',
          input,
          {
            key: createPublicKey({ key: spki, format: 'der', type: 'spki' }),
            dsaEncoding: 'ieee-p1363',
          },
          signature,
        );
      } finally {
        input.fill(0);
        signature.fill(0);
        spki.fill(0);
      }
    },
  };
}
