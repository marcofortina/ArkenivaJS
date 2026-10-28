// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  MagicLinksPluginSettings,
  KeyedDigestProvider,
  MagicLinkAuthority,
  SecurityTransactionalStore,
} from './contracts.js';
import { fields, property, method, integer, text, failure } from './validation.js';

/** Capture all provider methods before startup; request objects cannot replace them. */
export function capture(input: MagicLinksPluginSettings) {
  try {
    const data = fields(input, [
        'stateStore',
        'hmac',
        'signingKeyRef',
        'authority',
        'trustedBaseUrl',
        'ttlMs',
        'maxClaimsPerHour',
      ]),
      storage = fields(data.stateStore, ['store', 'securityLevel', 'operationTimeoutMs']);
    if (
      !['production', 'test-only'].includes(storage.securityLevel as string) ||
      property(data.hmac, 'algorithm') !== 'HMAC-SHA256'
    )
      throw failure('EK_CONFIG_INVALID');
    const url = new URL(text(data.trustedBaseUrl, 2048));
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search)
      throw failure('EK_CONFIG_INVALID');
    const classification = [
      storage.securityLevel,
      property(storage.store, 'securityLevel'),
      property(data.hmac, 'usage'),
      property(data.authority, 'usage'),
    ];
    if (
      classification.some(
        (value) => value !== undefined && value !== 'production' && value !== 'test-only',
      )
    )
      throw failure('EK_CONFIG_INVALID');
    const store = Object.freeze(
      Object.fromEntries(
        [
          'claimOnce',
          'read',
          'compareAndSet',
          'atomicBatch',
          'listByOwner',
          'bumpOwnerEpoch',
          'currentOwnerEpoch',
        ].map((name) => [name, method(storage.store, name)]),
      ),
    ) as unknown as SecurityTransactionalStore;
    return Object.freeze({
      store,
      hmac: Object.freeze({
        algorithm: 'HMAC-SHA256' as const,
        digest: method<KeyedDigestProvider['digest']>(data.hmac, 'digest'),
        verify: method<KeyedDigestProvider['verify']>(data.hmac, 'verify'),
      }),
      require: method<MagicLinkAuthority['require']>(data.authority, 'require'),
      keyRef: text(data.signingKeyRef, 256),
      baseUrl: url.href,
      ttlMs: integer(data.ttlMs, 900000),
      maxClaims: integer(data.maxClaimsPerHour, 100000),
      timeoutMs: integer(storage.operationTimeoutMs, 30000),
      maxConcurrent: 16,
      testOnly: classification.includes('test-only'),
    });
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export type Settings = ReturnType<typeof capture>;
