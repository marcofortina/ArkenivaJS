// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createPublicKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { calculateJwkThumbprint, exportJWK } from 'jose';
import type { JWK } from 'jose';
import { KitError } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import type { FederationSignatureAlgorithm } from './contracts.js';
import { failure } from './validation.js';
import { loadPrivateMaterial } from './private-key.js';

export type { FederationSignatureAlgorithm } from './contracts.js';
export interface FederationSigningMaterial {
  readonly key: ReturnType<KeyObject['toCryptoKey']>;
  readonly publicJwk: Readonly<JWK>;
  readonly kid: string;
  readonly algorithm: FederationSignatureAlgorithm;
  readonly expiresAt: number;
  readonly check: () => void;
}
function parameters(key: KeyObject, algorithm: FederationSignatureAlgorithm) {
  if (['RS256', 'RS512', 'PS256', 'PS384', 'PS512'].includes(algorithm)) {
    if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048)
      throw failure('EK_EID_FEDERATION');
    return {
      name: algorithm.startsWith('RS') ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS',
      hash: 'SHA-' + algorithm.slice(2),
    };
  }
  const curves = {
    ES256: ['prime256v1', 'P-256'],
    ES384: ['secp384r1', 'P-384'],
    ES512: ['secp521r1', 'P-521'],
  } as const;
  const curve = curves[algorithm as keyof typeof curves];
  if (!curve || key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== curve[0])
    throw failure('EK_EID_FEDERATION');
  return { name: 'ECDSA', namedCurve: curve[1] };
}
/** Import only the activated profile's external key and expose no extractable private material. */
export async function loadFederationSigningKey(
  call: FederationCall,
  settings: Settings,
  profileId: string,
  algorithm: FederationSignatureAlgorithm,
): Promise<FederationSigningMaterial> {
  try {
    call.check();
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId);
    if (
      !profile ||
      !['RS256', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'].includes(algorithm)
    )
      throw failure('EK_EID_PROFILE');
    const { native, expiresAt, check } = await loadPrivateMaterial(
      call,
      settings,
      profile.signingKeyRef,
    );
    const key = native.toCryptoKey(parameters(native, algorithm), false, ['sign']),
      publicJwk = await call.step(() => exportJWK(createPublicKey(native))),
      kid = await call.step(() => calculateJwkThumbprint(publicJwk));
    call.check();
    check();
    return Object.freeze({
      key,
      publicJwk: freezeData({ ...publicJwk, kid, use: 'sig', alg: algorithm }),
      kid,
      algorithm,
      expiresAt,
      check,
    });
  } catch (error) {
    if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) throw error;
    throw failure('EK_EID_FEDERATION');
  }
}
