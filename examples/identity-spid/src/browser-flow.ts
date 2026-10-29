// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { timingSafeEqual } from 'node:crypto';
import type {
  FederatedLogin,
  SpidService,
  FederationAssurance,
  OperationOptions,
} from '@arkenivajs/identity-spid';

const cookieName = '__Host-spid-flow';
const headers = Object.freeze({
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
});
export const clearBrowserCookie =
  cookieName + '=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0';
function reject(): never {
  throw new Error('The browser authentication transaction is unavailable');
}
function reference(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}(?![\s\S])/u.test(value)) reject();
  return value;
}
function https(value: string): URL {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 65536 || /[\r\n]/u.test(value))
    reject();
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return reject();
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) reject();
  return parsed;
}
/** Use only a transfer returned by the selected service; the cookie grants no account identity. */
export function browserRedirect(login: FederatedLogin) {
  const state = reference(login.transactionId),
    target = https(login.redirectUrl),
    remaining = Date.parse(login.expiresAt) - Date.now();
  if (!Number.isFinite(remaining) || remaining <= 0) reject();
  return Object.freeze({
    status: 303 as const,
    headers: Object.freeze({
      ...headers,
      location: target.href,
      'set-cookie':
        cookieName +
        '=' +
        state +
        '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=' +
        Math.min(300, Math.ceil(remaining / 1000)),
    }),
    body: '',
  });
}
/** A fixed configured callback and first-party cookie are checked before federation/provider work. */
export function verifyBrowserCallback(
  cookieHeader: string | undefined,
  responseUrl: string,
  configuredCallbackUri: string,
): string {
  if (typeof cookieHeader !== 'string' || Buffer.byteLength(cookieHeader) > 8192) reject();
  const cookies = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.startsWith(cookieName + '='));
  if (cookies.length !== 1) reject();
  const expected = reference(cookies[0]!.slice(cookieName.length + 1)),
    response = https(responseUrl),
    callback = https(configuredCallbackUri);
  if (response.origin !== callback.origin || response.pathname !== callback.pathname) reject();
  for (const name of new Set(callback.searchParams.keys())) {
    const values = callback.searchParams.getAll(name),
      actual = response.searchParams.getAll(name);
    if (values.length !== actual.length || values.some((value, index) => value !== actual[index]))
      reject();
  }
  if (response.searchParams.getAll('state').length !== 1) reject();
  const state = reference(response.searchParams.get('state'));
  if (!timingSafeEqual(Buffer.from(expected, 'ascii'), Buffer.from(state, 'ascii'))) reject();
  return response.href;
}
export async function beginBrowserLogin(
  service: SpidService,
  context: Parameters<SpidService['beginAuthentication']>[0],
  assurance: FederationAssurance,
  options?: OperationOptions,
) {
  return browserRedirect(await service.beginAuthentication(context, assurance, options));
}
/** Apply the clearing header even on rejection; the service independently enforces shared one-use consumption. */
export async function consumeBrowserLogin(
  service: SpidService,
  cookieHeader: string | undefined,
  responseUrl: string,
  configuredCallbackUri: string,
  options?: OperationOptions,
) {
  const response = verifyBrowserCallback(cookieHeader, responseUrl, configuredCallbackUri);
  return Object.freeze({
    identity: await service.consumeAuthentication(response, options),
    headers: Object.freeze({ ...headers, 'set-cookie': clearBrowserCookie }),
  });
}
