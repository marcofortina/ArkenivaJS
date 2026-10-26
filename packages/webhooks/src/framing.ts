// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHmac, timingSafeEqual, createHash } from 'node:crypto';
import type { WebhookContext } from './contracts.js';
import { failure } from './validation.js';

/** Versioned JSON-array framing escapes metadata delimiters; raw body bytes are appended unchanged. */
export function prefix(context: WebhookContext, tenantId: string): Buffer {
  return Buffer.from(
    JSON.stringify([
      'arkenivajs.webhooks.v1',
      tenantId,
      context.destinationId,
      context.eventId,
      context.timestamp,
      context.nonce,
      context.keyId,
    ]) + '\n',
    'utf8',
  );
}
/** Native HMAC-SHA256; only the owned key copy is erased after use. */
export function mac(
  body: Uint8Array,
  context: WebhookContext,
  tenantId: string,
  key: Uint8Array,
): string {
  if (
    !(key instanceof Uint8Array) ||
    key.byteLength < 32 ||
    key.byteLength > 4096 ||
    (typeof SharedArrayBuffer !== 'undefined' && key.buffer instanceof SharedArrayBuffer)
  )
    throw failure('EK_WEBHOOK_SIGNATURE');
  const owned = Buffer.from(key);
  try {
    return createHmac('sha256', owned)
      .update(prefix(context, tenantId))
      .update(body)
      .digest('base64url');
  } finally {
    owned.fill(0);
  }
}
/** Canonical length validation precedes the native constant-time comparison. */
export function equal(expected: string, supplied: string): boolean {
  const left = Buffer.from(expected, 'base64url'),
    right = Buffer.from(supplied, 'base64url');
  return right.length === 32 && left.length === 32 && timingSafeEqual(left, right);
}
/** A nonce cannot be reused after key rotation; ownership is verified outside this hash. */
export function replayKey(
  context: WebhookContext,
  owner: Readonly<{ issuer: string; subject: string; tenantId: string }>,
): string {
  return createHash('sha256')
    .update(
      JSON.stringify([
        'arkenivajs.webhooks.replay.v1',
        owner.issuer,
        owner.subject,
        owner.tenantId,
        context.destinationId,
        context.nonce,
      ]),
    )
    .digest('hex');
}
