// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { BlockList, isIP } from 'node:net';
import type {
  SecurityHttpPluginSettings,
  SecurityTransactionalStore,
  HttpSecurityAuthority,
  KeyedDigestProvider,
  CookieSessionProvider,
  CookieSecurityRoute,
} from './contracts.js';
import { fields, array, text, integer, origin, method, failure } from './validation.js';
import { headerPolicy } from './headers.js';

function classification(input: unknown, key: string): unknown {
  if (!input || typeof input !== 'object') return undefined;
  let current: object | null = input;
  for (let depth = 0; current && depth < 64; depth++) {
    const value = Object.getOwnPropertyDescriptor(current, key);
    if (value) {
      if (!('value' in value)) throw failure();
      return value.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw failure();
  return undefined;
}

export function capture(input: SecurityHttpPluginSettings) {
  try {
    const value = fields(input, [
      'policy',
      'csrfStore',
      'csrfHmac',
      'csrfKeyRef',
      'authority',
      'allowedOrigins',
      'cookieRoutes',
      'cookieSession',
      'trustedProxyCidrs',
    ]);
    const policy = headerPolicy(value.policy),
      store = fields(value.csrfStore, ['store', 'securityLevel', 'operationTimeoutMs']);
    if (!['production', 'test-only'].includes(store.securityLevel as string)) throw failure();
    if (
      !value.csrfHmac ||
      Object.getOwnPropertyDescriptor(value.csrfHmac, 'algorithm')?.value !== 'HMAC-SHA256'
    )
      throw failure();
    const origins = Object.freeze(
      array(value.allowedOrigins === undefined ? [] : value.allowedOrigins, 32).map(origin),
    );
    if (new Set(origins).size !== origins.length || (policy.csrfEnabled && !origins.length))
      throw failure();
    const routes = Object.freeze(
      array(value.cookieRoutes === undefined ? [] : value.cookieRoutes, 128).map(
        (entry): CookieSecurityRoute => {
          const route = fields(entry, ['method', 'path']);
          if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method as string)) throw failure();
          const path = text(route.path, 256);
          if (!path.startsWith('/') || /[?#*\\]/.test(path) || path.includes('..')) throw failure();
          return Object.freeze({ method: route.method as CookieSecurityRoute['method'], path });
        },
      ),
    );
    if (
      new Set(routes.map((r) => r.method + ':' + r.path)).size !== routes.length ||
      (routes.length && !policy.csrfEnabled)
    )
      throw failure();
    const session =
      value.cookieSession === undefined
        ? undefined
        : { resolve: method<CookieSessionProvider['resolve']>(value.cookieSession, 'resolve') };
    if (routes.length && !session) throw failure();
    const proxy = new BlockList();
    for (const entry of array(
      value.trustedProxyCidrs === undefined ? [] : value.trustedProxyCidrs,
      32,
    )) {
      const parts = text(entry, 64).split('/'),
        family = isIP(parts[0]!);
      if (
        parts.length !== 2 ||
        !family ||
        !/^(0|[1-9][0-9]{0,2})$/.test(parts[1]!) ||
        Number(parts[1]) > (family === 4 ? 32 : 128)
      )
        throw failure();
      proxy.addSubnet(parts[0]!, Number(parts[1]), family === 4 ? 'ipv4' : 'ipv6');
    }
    const classifications = [
      store.securityLevel,
      classification(store.store, 'securityLevel'),
      classification(value.csrfHmac, 'usage'),
      classification(value.authority, 'usage'),
      classification(value.cookieSession, 'usage'),
    ];
    if (
      classifications.some(
        (level) => level !== undefined && level !== 'production' && level !== 'test-only',
      )
    )
      throw failure();
    const productionUnsafe =
      origins.some((v) => new URL(v).protocol !== 'https:') ||
      classifications.includes('test-only');
    return Object.freeze({
      initialPolicy: policy,
      origins,
      routes,
      session,
      productionUnsafe,
      permitsProxy(address: string) {
        const family = isIP(address);
        return !!family && proxy.check(address, family === 4 ? 'ipv4' : 'ipv6');
      },
      keyRef: text(value.csrfKeyRef, 256),
      timeoutMs: Math.min(integer(store.operationTimeoutMs, 30000), 5000),
      maxConcurrent: 16,
      authority: { require: method<HttpSecurityAuthority['require']>(value.authority, 'require') },
      hmac: {
        digest: method<KeyedDigestProvider['digest']>(value.csrfHmac, 'digest'),
        verify: method<KeyedDigestProvider['verify']>(value.csrfHmac, 'verify'),
      },
      store: Object.fromEntries(
        [
          'read',
          'claimOnce',
          'compareAndSet',
          'atomicBatch',
          'listByOwner',
          'bumpOwnerEpoch',
          'currentOwnerEpoch',
        ].map((name) => [name, method(valueOfStore(store), name)]),
      ) as unknown as SecurityTransactionalStore,
    });
  } catch {
    throw failure();
  }
}
const valueOfStore = (store: Record<string, unknown>) => store.store;
export type Settings = ReturnType<typeof capture>;
