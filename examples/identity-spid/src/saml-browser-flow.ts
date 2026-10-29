// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  FederatedLogin,
  SpidService,
  FederationAssurance,
  OperationOptions,
} from '@arkenivajs/identity-spid';
import { types } from 'node:util';

const cookie = '__Host-spid-saml-flow',
  headers = Object.freeze({
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
export const clearSamlBrowserCookie =
  cookie + '=; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=0';
function reject(): never {
  throw new Error('The SAML browser authentication transaction is unavailable');
}
function https(input: unknown): URL {
  if (typeof input !== 'string' || Buffer.byteLength(input) > 8192 || /\s/u.test(input)) reject();
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return reject();
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) reject();
  return url;
}
/** A separate host cookie supports the required cross-site POST; it never carries account authority. */
export function samlBrowserRedirect(login: FederatedLogin) {
  if (
    typeof login.transactionId !== 'string' ||
    login.transactionId.length !== 64 ||
    !/^[a-f0-9]{64}$/u.test(login.transactionId)
  )
    reject();
  const target = https(login.redirectUrl),
    remaining = Date.parse(login.expiresAt) - Date.now();
  if (!Number.isFinite(remaining) || remaining <= 0) reject();
  return Object.freeze({
    status: 303 as const,
    headers: Object.freeze({
      ...headers,
      location: target.href,
      'set-cookie': `${cookie}=${login.transactionId}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=${Math.min(300, Math.ceil(remaining / 1000))}`,
    }),
    body: '',
  });
}
/** Enforce the application-owned ACS and cookie before any native verification or provider work. */
export function verifySamlBrowserCallback(
  cookieHeader: string | undefined,
  request: Readonly<{ method: string; url: string; contentType: string | undefined; body: string }>,
  configuredCallbackUri: string,
  configuredIssuer: string,
) {
  if (
    typeof cookieHeader !== 'string' ||
    Buffer.byteLength(cookieHeader) > 8192 ||
    /[\r\n]/u.test(cookieHeader)
  )
    reject();
  if (
    !request ||
    typeof request !== 'object' ||
    types.isProxy(request) ||
    Object.getPrototypeOf(request) !== Object.prototype
  )
    reject();
  for (const name of Reflect.ownKeys(request)) {
    const descriptor = Object.getOwnPropertyDescriptor(request, name)!;
    if (
      typeof name !== 'string' ||
      !['method', 'url', 'contentType', 'body'].includes(name) ||
      !('value' in descriptor) ||
      !descriptor.enumerable
    )
      reject();
  }
  const cookies = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.startsWith(cookie + '='));
  if (cookies.length !== 1) reject();
  const transactionId = cookies[0]!.slice(cookie.length + 1);
  if (transactionId.length !== 64 || !/^[a-f0-9]{64}$/u.test(transactionId)) reject();
  if (
    request.method !== 'POST' ||
    https(request.url).href !== https(configuredCallbackUri).href ||
    typeof request.contentType !== 'string' ||
    !/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/iu.test(request.contentType) ||
    typeof request.body !== 'string' ||
    !request.body ||
    Buffer.byteLength(request.body) > 65536 ||
    /%(?![a-f0-9]{2})/iu.test(request.body)
  )
    reject();
  const form = new URLSearchParams(request.body);
  https(configuredIssuer);
  if (
    [...form.keys()].some((name) => name !== 'SAMLResponse' && name !== 'RelayState') ||
    form.getAll('SAMLResponse').length !== 1 ||
    form.getAll('RelayState').length !== 1
  )
    reject();
  const samlResponse = form.get('SAMLResponse')!,
    relayState = form.get('RelayState')!;
  if (
    relayState.length !== 41 ||
    !/^_[a-f0-9]{40}$/u.test(relayState) ||
    !samlResponse ||
    Buffer.from(samlResponse, 'base64').toString('base64') !== samlResponse
  )
    reject();
  // Preserve the configured EntityID exactly; URL normalization must not add a trailing slash.
  return Object.freeze({ transactionId, issuer: configuredIssuer, relayState, samlResponse });
}
export async function beginSamlBrowserLogin(
  service: SpidService,
  context: Parameters<SpidService['beginAuthentication']>[0],
  assurance: FederationAssurance,
  options?: OperationOptions,
) {
  return samlBrowserRedirect(await service.beginAuthentication(context, assurance, options));
}
/** The application must apply the clearing header on failures as well as success. */
export async function consumeSamlBrowserLogin(
  service: SpidService,
  cookieHeader: string | undefined,
  request: Parameters<typeof verifySamlBrowserCallback>[1],
  configuredCallbackUri: string,
  configuredIssuer: string,
  options?: OperationOptions,
) {
  const input = verifySamlBrowserCallback(
    cookieHeader,
    request,
    configuredCallbackUri,
    configuredIssuer,
  );
  return Object.freeze({
    identity: await service.consumeAuthentication(input, options),
    headers: Object.freeze({ ...headers, 'set-cookie': clearSamlBrowserCookie }),
  });
}
