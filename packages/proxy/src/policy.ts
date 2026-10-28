// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isIP } from 'node:net';
import { types, toUSVString } from 'node:util';
import ipaddr from 'ipaddr.js';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
import type { ProxyPluginSettings, ProxyRouteConfig } from './contracts.js';
import type { TlsProfile } from '@arkenivajs/security-mtls';

export function failure(code: ErrorCode = 'EK_PROXY_CONFIG'): KitError {
  const messages: Partial<Record<ErrorCode, string>> = {
    EK_PROXY_CONFIG: 'The fixed upstream proxy configuration is invalid',
    EK_PROXY_POLICY: 'The proxy request is not permitted by policy',
    EK_PROXY_UPSTREAM: 'The upstream service is unavailable',
    EK_PROXY_TIMEOUT: 'The upstream operation exceeded its deadline',
    EK_PROXY_BODY_LIMIT: 'The proxy message exceeds its byte limit',
    EK_AUTH_REQUIRED: 'A verified authenticated identity is required',
    EK_AUTH_INVALID: 'The authenticated identity could not be verified',
    EK_AUTH_FORBIDDEN: 'The authenticated identity is not authorized',
    EK_BACKEND_UNAVAILABLE: 'The proxy operation cannot be admitted',
    EK_RESOURCE_CLOSED: 'The proxy service is closed',
    EK_ABORTED: 'The proxy request was cancelled',
  };
  return new KitError({ code, message: messages[code] ?? 'The proxy operation failed' });
}
export function fields(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    types.isProxy(value) ||
    ![null, Object.prototype].includes(Object.getPrototypeOf(value))
  )
    throw failure();
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      !allowed.includes(key) ||
      !descriptor ||
      !('value' in descriptor)
    )
      throw failure();
    result[key] = descriptor.value;
  }
  return result;
}
export function text(value: unknown, maximum = 2048): string {
  if (
    typeof value !== 'string' ||
    !value ||
    Buffer.byteLength(value) > maximum ||
    toUSVString(value) !== value ||
    [...value].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    throw failure();
  return value;
}
function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw failure();
  return value as number;
}
function list(value: unknown, maximum: number, minimum = 1): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    value.length < minimum ||
    value.length > maximum
  )
    throw failure();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== value.length + 1) throw failure();
  return Object.freeze(
    Array.from({ length: value.length }, (_, i) => {
      const descriptor = descriptors[String(i)];
      if (!descriptor || !('value' in descriptor)) throw failure();
      return descriptor.value;
    }),
  );
}
function path(value: unknown, empty = false): string {
  if (empty && value === '') return '';
  const result = text(value, 512);
  if (
    !/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]*$/.test(result) ||
    (result.length > 1 && result.endsWith('/'))
  )
    throw failure();
  return result;
}
export function hostname(value: string): string {
  return value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
}
/** Only canonical native IP forms enter address classification, including mapped IPv4. */
export function allowedAddress(
  address: string,
  policy: ProxyRouteConfig['destinationPolicy'],
): boolean {
  if (!isIP(address) || address.includes('%')) return false;
  const parsed = ipaddr.process(address);
  if (policy.kind === 'public-only') return parsed.range() === 'unicast';
  return policy.allowedCidrs.some((range) => {
    const [network, bits] = ipaddr.parseCIDR(range);
    return parsed.kind() === network.kind() && parsed.match(network, bits);
  });
}
function route(input: unknown): Readonly<ProxyRouteConfig> {
  const value = fields(input, [
    'routeId',
    'prefix',
    'upstreamOrigin',
    'rewritePrefix',
    'methods',
    'auth',
    'maxRequestBytes',
    'maxResponseBytes',
    'timeoutMs',
    'destinationPolicy',
    'upstreamCaFile',
    'upstreamTlsProfile',
    'identityDelegation',
    'serviceCredentialSecretRef',
  ]);
  const routeId = text(value.routeId, 64);
  if (!/^[a-z][a-z0-9-]*$/.test(routeId)) throw failure();
  const upstreamOrigin = text(value.upstreamOrigin),
    url = new URL(upstreamOrigin);
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    upstreamOrigin !== url.origin ||
    url.username ||
    url.password ||
    url.hostname.endsWith('.')
  )
    throw failure();
  const auth = fields(value.auth, ['required', 'scopes', 'reason']);
  if (
    typeof auth.required !== 'boolean' ||
    (auth.required ? auth.reason !== undefined : auth.scopes !== undefined)
  )
    throw failure();
  const capturedAuth = auth.required
    ? Object.freeze({
        required: true as const,
        ...(auth.scopes === undefined
          ? {}
          : { scopes: Object.freeze(list(auth.scopes, 64, 0).map((v) => text(v, 128))) }),
      })
    : Object.freeze({ required: false as const, reason: text(auth.reason, 512) });
  const destination = fields(value.destinationPolicy, ['kind', 'allowedHosts', 'allowedCidrs']);
  let destinationPolicy: ProxyRouteConfig['destinationPolicy'];
  if (destination.kind === 'public-only') {
    if (destination.allowedHosts !== undefined || destination.allowedCidrs !== undefined)
      throw failure();
    destinationPolicy = Object.freeze({ kind: 'public-only' });
  } else if (destination.kind === 'private-allowlisted') {
    const allowedHosts = list(destination.allowedHosts, 64).map((v) => text(v, 253));
    if (!allowedHosts.includes(hostname(url.hostname))) throw failure();
    const allowedCidrs = list(destination.allowedCidrs, 64).map((v) => {
      const cidr = text(v, 64),
        [ip, bits] = cidr.split('/');
      if (!ip || !isIP(ip) || bits === undefined || !/^\d+$/.test(bits)) throw failure();
      const parsed = ipaddr.parseCIDR(cidr);
      if (parsed[0] instanceof ipaddr.IPv6 && parsed[0].isIPv4MappedAddress()) throw failure();
      return cidr;
    });
    destinationPolicy = Object.freeze({
      kind: 'private-allowlisted',
      allowedHosts: Object.freeze(allowedHosts),
      allowedCidrs: Object.freeze(allowedCidrs),
    });
  } else throw failure();
  if (isIP(hostname(url.hostname)) && !allowedAddress(hostname(url.hostname), destinationPolicy))
    throw failure('EK_PROXY_POLICY');
  const delegation = value.identityDelegation ?? 'none';
  let upstreamTlsProfile: TlsProfile | undefined;
  if (value.upstreamTlsProfile !== undefined) {
    if (url.protocol !== 'https:' || value.upstreamCaFile !== undefined) throw failure();
    const profile = fields(value.upstreamTlsProfile, [
      'trustRootsRef',
      'certRef',
      'keyRef',
      'allowedIdentities',
      'minTlsVersion',
      'alpnProtocols',
      'revocation',
    ]);
    if (
      profile.alpnProtocols !== undefined &&
      !list(profile.alpnProtocols, 16).includes('http/1.1')
    )
      throw failure();
    if (
      !['crl-required', 'ocsp-required', 'approved-online-checker'].includes(
        profile.revocation as string,
      ) ||
      (profile.minTlsVersion !== undefined &&
        !['TLSv1.2', 'TLSv1.3'].includes(profile.minTlsVersion as string))
    )
      throw failure();
    upstreamTlsProfile = Object.freeze({
      trustRootsRef: text(profile.trustRootsRef, 256),
      certRef: text(profile.certRef, 256),
      keyRef: text(profile.keyRef, 256),
      allowedIdentities: Object.freeze(
        list(profile.allowedIdentities, 64).map((value) => text(value, 2048)),
      ),
      revocation: profile.revocation as TlsProfile['revocation'],
      ...(profile.minTlsVersion === undefined
        ? {}
        : { minTlsVersion: profile.minTlsVersion as 'TLSv1.2' | 'TLSv1.3' }),
      ...(profile.alpnProtocols === undefined
        ? {}
        : {
            alpnProtocols: Object.freeze(
              list(profile.alpnProtocols, 16).map((value) => text(value, 255)),
            ),
          }),
    });
  }
  if (
    !['none', 'validated-service-credential'].includes(delegation as string) ||
    (delegation === 'none' && value.serviceCredentialSecretRef !== undefined)
  )
    throw failure();
  const methods = list(value.methods, 6).map((method) => {
    if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method as string))
      throw failure();
    return method as ProxyRouteConfig['methods'][number];
  });
  if (new Set(methods).size !== methods.length) throw failure();
  return Object.freeze({
    routeId,
    prefix: path(value.prefix),
    upstreamOrigin,
    ...(value.rewritePrefix === undefined
      ? {}
      : { rewritePrefix: path(value.rewritePrefix, true) }),
    methods: Object.freeze(methods),
    auth: capturedAuth,
    destinationPolicy,
    maxRequestBytes: integer(value.maxRequestBytes, 1073741824),
    maxResponseBytes: integer(value.maxResponseBytes, 1073741824),
    timeoutMs: integer(value.timeoutMs, 30000),
    ...(value.upstreamCaFile === undefined
      ? {}
      : { upstreamCaFile: text(value.upstreamCaFile, 4096) }),
    ...(upstreamTlsProfile ? { upstreamTlsProfile } : {}),
    identityDelegation: delegation as 'none' | 'validated-service-credential',
    ...(delegation === 'validated-service-credential'
      ? { serviceCredentialSecretRef: text(value.serviceCredentialSecretRef, 512) }
      : {}),
  });
}
export function capture(input: ProxyPluginSettings) {
  try {
    const value = fields(input, ['routes', 'resolveSecret']),
      routes = list(value.routes, 32).map(route);
    if (
      new Set(routes.map((v) => v.routeId)).size !== routes.length ||
      routes.some((v, i) =>
        routes.some(
          (other, j) =>
            j < i &&
            (v.prefix === '/' ||
              other.prefix === '/' ||
              v.prefix === other.prefix ||
              v.prefix.startsWith(other.prefix + '/') ||
              other.prefix.startsWith(v.prefix + '/')),
        ),
      )
    )
      throw failure();
    if (
      value.resolveSecret !== undefined &&
      (typeof value.resolveSecret !== 'function' || types.isProxy(value.resolveSecret))
    )
      throw failure();
    if (
      routes.some((v) => v.identityDelegation === 'validated-service-credential') &&
      !value.resolveSecret
    )
      throw failure();
    return Object.freeze({
      routes: Object.freeze(routes),
      resolveSecret: value.resolveSecret as ProxyPluginSettings['resolveSecret'],
    });
  } catch (error) {
    if (error instanceof KitError && error.code === 'EK_PROXY_POLICY') throw error;
    throw failure();
  }
}
