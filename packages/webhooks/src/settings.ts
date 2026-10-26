// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { BlockList, isIP } from 'node:net';
import type {
  WebhooksPluginSettings,
  SecretProvider,
  SecurityTransactionalStore,
  WebhookAuthority,
  WebhookVerificationKey,
} from './contracts.js';
import { array, fields, integer, instant, text, failure } from './validation.js';

function property(input: unknown, name: string): unknown {
  if (!input || typeof input !== 'object') throw failure();
  let current: object | null = input;
  for (let depth = 0; current && depth < 64; depth++) {
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) {
      if (!('value' in descriptor)) throw failure();
      return descriptor.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw failure();
  return undefined;
}
function method<T>(input: unknown, name: string): T {
  const value = property(input, name);
  if (typeof value !== 'function') throw failure();
  return value.bind(input) as T;
}
/** Fixed DNS destinations and native CIDR policy, with no caller-selected URL or credentials. */
export function capture(input: WebhooksPluginSettings) {
  try {
    const value = fields(input, [
        'destinations',
        'secretProvider',
        'nonceStore',
        'authority',
        'policy',
      ]),
      policy = fields(value.policy, [
        'maxConcurrent',
        'timeoutMs',
        'maxInputBytes',
        'maxOutputBytes',
      ]),
      storage = fields(value.nonceStore, ['store', 'securityLevel', 'operationTimeoutMs']);
    if (!['production', 'test-only'].includes(storage.securityLevel as string)) throw failure();
    const classifications = [
      storage.securityLevel,
      property(storage.store, 'securityLevel'),
      property(value.secretProvider, 'usage'),
      property(value.authority, 'usage'),
    ];
    if (
      classifications.some(
        (level) => level !== undefined && level !== 'production' && level !== 'test-only',
      )
    )
      throw failure();
    const destinations = array(value.destinations, 16).map((item) => {
      const profile = fields(item, [
          'name',
          'origin',
          'hmacKeyRef',
          'allowedCidrs',
          'maxRetries',
          'timeoutMs',
          'idempotent',
          'verificationKeys',
        ]),
        name = text(profile.name, 64);
      if (!/^[a-z][a-z0-9_-]*$/.test(name)) throw failure();
      const origin = new URL(text(profile.origin, 2048)),
        hostname = origin.hostname.replace(/^\[|\]$/g, '');
      if (
        !['https:', 'http:'].includes(origin.protocol) ||
        origin.username ||
        origin.password ||
        origin.pathname !== '/' ||
        origin.search ||
        origin.hash ||
        (origin.protocol === 'http:' && !['127.0.0.1', '::1', 'localhost'].includes(hostname))
      )
        throw failure();
      const cidrs = array(profile.allowedCidrs, 32).map((item) => text(item, 64)),
        allowed = new BlockList();
      for (const cidr of cidrs) {
        const parts = cidr.split('/'),
          family = isIP(parts[0]!);
        if (
          parts.length !== 2 ||
          !family ||
          !/^(0|[1-9][0-9]{0,2})$/.test(parts[1]!) ||
          Number(parts[1]) > (family === 4 ? 32 : 128)
        )
          throw failure();
        allowed.addSubnet(parts[0]!, Number(parts[1]), family === 4 ? 'ipv4' : 'ipv6');
      }
      const permits = (address: string) => {
        const family = isIP(address);
        return !!family && allowed.check(address, family === 4 ? 'ipv4' : 'ipv6');
      };
      if (isIP(hostname) && !permits(hostname)) throw failure();
      if (profile.idempotent !== undefined && typeof profile.idempotent !== 'boolean')
        throw failure();
      const maxRetries = integer(profile.maxRetries, 2, 0);
      if (maxRetries && profile.idempotent !== true) throw failure();
      const verificationKeys =
        profile.verificationKeys === undefined
          ? []
          : array(profile.verificationKeys, 16, 0).map((item): WebhookVerificationKey => {
              const key = fields(item, ['keyId', 'hmacKeyRef', 'expiresAt']);
              return Object.freeze({
                keyId: text(key.keyId, 128),
                hmacKeyRef: text(key.hmacKeyRef),
                expiresAt: instant(key.expiresAt),
              });
            });
      if (new Set(verificationKeys.map((key) => key.keyId)).size !== verificationKeys.length)
        throw failure();
      return Object.freeze({
        name,
        origin: origin.origin,
        hostname,
        cleartext: origin.protocol === 'http:',
        permits,
        hmacKeyRef: text(profile.hmacKeyRef),
        maxRetries,
        timeoutMs: integer(profile.timeoutMs, 120000),
        idempotent: profile.idempotent === true,
        verificationKeys: Object.freeze(verificationKeys),
      });
    });
    if (new Set(destinations.map((profile) => profile.name)).size !== destinations.length)
      throw failure();
    const store = Object.freeze(
      Object.fromEntries(
        [
          'read',
          'claimOnce',
          'compareAndSet',
          'atomicBatch',
          'listByOwner',
          'bumpOwnerEpoch',
          'currentOwnerEpoch',
        ].map((name) => [name, method(storage.store, name)]),
      ),
    ) as unknown as SecurityTransactionalStore;
    return Object.freeze({
      destinations: Object.freeze(destinations),
      store,
      get: method<SecretProvider['get']>(value.secretProvider, 'get'),
      require: method<WebhookAuthority['require']>(value.authority, 'require'),
      testOnly: classifications.includes('test-only'),
      storeTimeoutMs: integer(storage.operationTimeoutMs, 120000),
      maxConcurrent: integer(policy.maxConcurrent, 16),
      timeoutMs: integer(policy.timeoutMs, 120000),
      maxInputBytes:
        policy.maxInputBytes === undefined ? 1048576 : integer(policy.maxInputBytes, 8388608),
      maxOutputBytes:
        policy.maxOutputBytes === undefined ? 65536 : integer(policy.maxOutputBytes, 1048576),
    });
  } catch {
    throw failure();
  }
}
export type Settings = ReturnType<typeof capture>;
export type Destination = Settings['destinations'][number];
