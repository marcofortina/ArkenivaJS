// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { SamlLoginRequest } from '@arkenivajs/security-saml';

const escape = (value: string) =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
/** Render only a service-owned transfer. The browser transaction cookie is bound separately at the ACS. */
export function browserTransfer(
  request: SamlLoginRequest,
): Readonly<{ status: 200 | 303; headers: Readonly<Record<string, string>>; body: string }> {
  const headers: Record<string, string> = {
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  };
  if (request.binding === 'redirect')
    return { status: 303, headers: { ...headers, location: request.redirectUrl }, body: '' };
  const destination = new URL(request.actionUrl);
  if (destination.protocol !== 'https:' || destination.username || destination.password)
    throw new Error('The SAML form requires a pinned HTTPS endpoint');
  headers['content-type'] = 'text/html; charset=utf-8';
  headers['content-security-policy'] =
    "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action " +
    destination.origin;
  return {
    status: 200,
    headers,
    body:
      '<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>Continue enterprise sign-in</title></head><body><form method="post" action="' +
      escape(destination.href) +
      '">' +
      Object.entries(request.fields)
        .map(
          ([name, value]) =>
            '<input type="hidden" name="' + escape(name) + '" value="' + escape(value) + '"/>',
        )
        .join('') +
      '<button type="submit">Continue sign-in</button></form></body></html>',
  };
}
