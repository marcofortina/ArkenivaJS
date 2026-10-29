// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createPublicKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { calculateJwkThumbprint, exportJWK } from 'jose';
import type { JWK } from 'jose';
import { KitError } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { FederationEncryptionPolicy } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import { loadPrivateMaterial } from './private-key.js';
import { failure } from './validation.js';

export interface FederationDecryptionMaterial {
  readonly keys: readonly {
    readonly key: ReturnType<KeyObject['toCryptoKey']>;
    readonly alg: FederationEncryptionPolicy['algorithm'];
    readonly kid: string;
  }[];
  readonly publicJwk: Readonly<JWK & { kid: string; use: 'enc' }>;
  readonly expiresAt: number;
  readonly check: () => void;
}
/** Use only captured response-encryption policies and the profile's separate external RSA key. */
export async function loadFederationDecryptionKey(
  call: FederationCall,
  settings: Settings,
  profileId: string,
): Promise<FederationDecryptionMaterial> {
  try {
    call.check();
    const registration = settings.profiles.find(
      (profile) => profile.profileId === profileId,
    )?.oidcRegistration;
    if (!registration) throw failure('EK_EID_PROFILE');
    const { native, expiresAt, check } = await loadPrivateMaterial(
      call,
      settings,
      registration.decryptionKeyRef,
    );
    if (
      native.asymmetricKeyType !== 'rsa' ||
      (native.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
    )
      throw failure('EK_EID_FEDERATION');
    const publicJwk = await call.step(() => exportJWK(createPublicKey(native))),
      kid = await call.step(() => calculateJwkThumbprint(publicJwk)),
      algorithms = new Set([
        registration.userInfoEncryption.algorithm,
        ...(registration.idTokenEncryption ? [registration.idTokenEncryption.algorithm] : []),
      ]),
      keys = [...algorithms].map((alg) =>
        Object.freeze({
          key: native.toCryptoKey(
            { name: 'RSA-OAEP', hash: alg === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256' },
            false,
            ['decrypt'],
          ),
          alg,
          kid,
        }),
      );
    call.check();
    check();
    return Object.freeze({
      keys: Object.freeze(keys),
      publicJwk: freezeData({ ...publicJwk, kid, use: 'enc' as const }),
      expiresAt,
      check,
    });
  } catch (error) {
    if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) throw error;
    throw failure('EK_EID_FEDERATION');
  }
}
