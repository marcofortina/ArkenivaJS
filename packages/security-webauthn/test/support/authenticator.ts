// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

/** Disposable authenticator producer; verification always uses the actual upstream server. */
export function authenticator() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const id = randomBytes(32).toString('base64url');
  const cose = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Uint8Array.from(Buffer.from(jwk.x!, 'base64url'))],
      [-3, Uint8Array.from(Buffer.from(jwk.y!, 'base64url'))],
    ]),
  );
  function make(
    challenge: string,
    registration: boolean,
    overrides: {
      rpId?: string;
      origin?: string;
      flags?: number;
      counter?: number;
      type?: string;
      crossOrigin?: boolean;
      topOrigin?: string;
      format?: string;
    } = {},
  ) {
    const clientData = Buffer.from(
      JSON.stringify({
        type: overrides.type ?? (registration ? 'webauthn.create' : 'webauthn.get'),
        challenge,
        origin: overrides.origin ?? 'https://login.example.test',
        ...(overrides.crossOrigin === undefined ? {} : { crossOrigin: overrides.crossOrigin }),
        ...(overrides.topOrigin === undefined ? {} : { topOrigin: overrides.topOrigin }),
      }),
    );
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(overrides.counter ?? 1);
    const credential = Buffer.from(id, 'base64url');
    const length = Buffer.alloc(2);
    length.writeUInt16BE(credential.length);
    const authData = Buffer.concat([
      createHash('sha256')
        .update(overrides.rpId ?? 'example.test')
        .digest(),
      Buffer.from([overrides.flags ?? (registration ? 0x45 : 0x05)]),
      counter,
      ...(registration ? [Buffer.alloc(16), length, credential, cose] : []),
    ]);
    const common = { id, rawId: id, type: 'public-key', clientExtensionResults: {} };
    const attestationStatement = new Map<string, number | Uint8Array>();
    if (registration && overrides.format === 'packed') {
      attestationStatement.set('alg', -7);
      attestationStatement.set(
        'sig',
        Uint8Array.from(
          sign(
            'sha256',
            Buffer.concat([authData, createHash('sha256').update(clientData).digest()]),
            privateKey,
          ),
        ),
      );
    }
    const response = registration
      ? {
          clientDataJSON: clientData.toString('base64url'),
          attestationObject: Buffer.from(
            isoCBOR.encode(
              new Map<string, string | Uint8Array | Map<string, number | Uint8Array>>([
                ['fmt', overrides.format ?? 'none'],
                ['authData', Uint8Array.from(authData)],
                ['attStmt', attestationStatement],
              ]),
            ),
          ).toString('base64url'),
          transports: ['internal'],
        }
      : {
          clientDataJSON: clientData.toString('base64url'),
          authenticatorData: authData.toString('base64url'),
          signature: sign(
            'sha256',
            Buffer.concat([authData, createHash('sha256').update(clientData).digest()]),
            privateKey,
          ).toString('base64url'),
        };
    return { ...common, response };
  }
  return {
    id,
    publicKey: cose,
    registration: (challenge: string, overrides?: Parameters<typeof make>[2]) =>
      make(challenge, true, overrides),
    authentication: (challenge: string, overrides?: Parameters<typeof make>[2]) =>
      make(challenge, false, overrides),
  };
}
