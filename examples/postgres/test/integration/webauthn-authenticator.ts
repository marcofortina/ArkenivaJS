// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

/** Disposable authenticator producer; verification always uses the actual upstream server. */
export function authenticator(algorithm: 'ES256' | 'RS256' | 'EdDSA' = 'ES256') {
  const { publicKey, privateKey } =
    algorithm === 'RS256'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : algorithm === 'EdDSA'
        ? generateKeyPairSync('ed25519')
        : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const id = randomBytes(32).toString('base64url');
  const bytes = (value: string) => Uint8Array.from(Buffer.from(value, 'base64url'));
  const coseAlgorithm = algorithm === 'RS256' ? -257 : algorithm === 'EdDSA' ? -8 : -7;
  const parameters: [number, number | Uint8Array][] =
    algorithm === 'RS256'
      ? [
          [1, 3],
          [-1, bytes(jwk.n!)],
          [-2, bytes(jwk.e!)],
        ]
      : algorithm === 'EdDSA'
        ? [
            [1, 1],
            [-1, 6],
            [-2, bytes(jwk.x!)],
          ]
        : [
            [1, 2],
            [-1, 1],
            [-2, bytes(jwk.x!)],
            [-3, bytes(jwk.y!)],
          ];
  const cose = isoCBOR.encode(
    new Map<number, number | Uint8Array>([[3, coseAlgorithm], ...parameters]),
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
      attestationStatement.set('alg', coseAlgorithm);
      attestationStatement.set(
        'sig',
        Uint8Array.from(
          sign(
            algorithm === 'EdDSA' ? null : 'sha256',
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
            algorithm === 'EdDSA' ? null : 'sha256',
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
