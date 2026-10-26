// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { toUSVString, types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { WebhookContext, WebhookSignature, WebhookEvent } from './contracts.js';

export const failure = (code: ErrorCode = 'EK_CONFIG_INVALID', unknown = false) =>
  new KitError({
    code,
    message: 'The webhook operation could not complete',
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
  });
/** Plain own data only; caller accessors and unknown fields are never evaluated. */
export function fields(input: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    ![null, Object.prototype].includes(Object.getPrototypeOf(input))
  )
    throw failure();
  const result: Record<string, unknown> = Object.create(null);
  for (const name of Reflect.ownKeys(input)) {
    if (typeof name !== 'string' || !names.includes(name)) throw failure();
    const descriptor = Object.getOwnPropertyDescriptor(input, name)!;
    if (!('value' in descriptor)) throw failure();
    result[name] = descriptor.value;
  }
  return result;
}
export function text(input: unknown, maximum = 256): string {
  if (
    typeof input !== 'string' ||
    !input ||
    input.length > maximum ||
    Buffer.byteLength(input) > maximum ||
    /[\p{Cc}\p{Cf}]/u.test(input) ||
    toUSVString(input) !== input
  )
    throw failure();
  return input;
}
export function integer(input: unknown, maximum: number, minimum = 1): number {
  if (!Number.isSafeInteger(input) || (input as number) < minimum || (input as number) > maximum)
    throw failure();
  return input as number;
}
export function array(input: unknown, maximum: number, minimum = 1): readonly unknown[] {
  if (
    !Array.isArray(input) ||
    input.length < minimum ||
    input.length > maximum ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure();
  return Object.freeze(
    Array.from({ length: input.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
      if (!descriptor || !('value' in descriptor)) throw failure();
      return descriptor.value as unknown;
    }),
  );
}
export function instant(input: unknown): string {
  const value = text(input, 24),
    epoch = Date.parse(value);
  if (!Number.isFinite(epoch) || new Date(epoch).toISOString() !== value) throw failure();
  return value;
}
/** Copy input bytes before any provider await; shared memory cannot change signed content. */
const typedArray = Object.getPrototypeOf(Uint8Array.prototype),
  bufferGetter = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!,
  lengthGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
export function bytes(input: unknown, maximum: number): Buffer {
  try {
    if (!types.isUint8Array(input)) throw failure();
    const length = lengthGetter.call(input) as number;
    if (length > maximum || types.isSharedArrayBuffer(bufferGetter.call(input))) throw failure();
    const result = Buffer.alloc(length);
    Uint8Array.prototype.set.call(result, input);
    return result;
  } catch {
    throw failure();
  }
}

export function context(input: WebhookContext): WebhookContext {
  const value = fields(input, ['destinationId', 'eventId', 'timestamp', 'nonce', 'keyId']);
  const nonce = text(value.nonce, 128);
  if (!/^[A-Za-z0-9_-]{22,128}$/.test(nonce)) throw failure();
  return Object.freeze({
    destinationId: text(value.destinationId, 64),
    eventId: text(value.eventId),
    timestamp: instant(value.timestamp),
    nonce,
    keyId: text(value.keyId, 128),
  });
}
export function signature(input: WebhookSignature): WebhookSignature {
  const value = fields(input, ['algorithm', 'keyId', 'timestamp', 'nonce', 'signature']);
  const digest = text(value.signature, 43);
  if (
    value.algorithm !== 'hmac-sha256' ||
    !/^[A-Za-z0-9_-]{43}$/.test(digest) ||
    Buffer.from(digest, 'base64url').toString('base64url') !== digest
  )
    throw failure('EK_WEBHOOK_SIGNATURE');
  const captured = context({
    destinationId: 'verification',
    eventId: 'verification',
    timestamp: value.timestamp as string,
    nonce: value.nonce as string,
    keyId: value.keyId as string,
  });
  return Object.freeze({
    algorithm: 'hmac-sha256',
    keyId: captured.keyId,
    timestamp: captured.timestamp,
    nonce: captured.nonce,
    signature: digest,
  });
}
/** Bound the full JSON tree before serialization; no application classes, accessors or cycles. */
export function event(input: WebhookEvent, maximum: number): WebhookEvent {
  const supplied = fields(input, ['id', 'type', 'payload']);
  let count = 0,
    size = 0;
  const parents = new Set<object>();
  const copy = (value: unknown, depth: number): unknown => {
    if (++count > 4096 || depth > 32) throw failure('EK_WEBHOOK_DELIVERY');
    size += typeof value === 'string' ? Buffer.byteLength(value) + 2 : 8;
    if (size > maximum) throw failure('EK_WEBHOOK_DELIVERY');
    if (
      value === null ||
      typeof value === 'boolean' ||
      typeof value === 'string' ||
      (typeof value === 'number' && Number.isFinite(value))
    ) {
      if (typeof value === 'string' && toUSVString(value) !== value) throw failure();
      return value;
    }
    if (!value || typeof value !== 'object' || parents.has(value)) throw failure();
    if (!Array.isArray(value) && ![null, Object.prototype].includes(Object.getPrototypeOf(value)))
      throw failure();
    parents.add(value);
    let result: unknown;
    if (Array.isArray(value)) result = array(value, 4096, 0).map((item) => copy(item, depth + 1));
    else {
      const record: Record<string, unknown> = Object.create(null);
      for (const name of Reflect.ownKeys(value)) {
        if (typeof name !== 'string' || ['__proto__', 'constructor', 'prototype'].includes(name))
          throw failure();
        size += Buffer.byteLength(name) + 3;
        if (size > maximum) throw failure('EK_WEBHOOK_DELIVERY');
        const descriptor = Object.getOwnPropertyDescriptor(value, name)!;
        if (!('value' in descriptor)) throw failure();
        record[name] = copy(descriptor.value, depth + 1);
      }
      result = record;
    }
    parents.delete(value);
    return result;
  };
  const result = {
    id: text(supplied.id),
    type: text(supplied.type, 128),
    payload: copy(supplied.payload, 0),
  };
  if (Buffer.byteLength(JSON.stringify(result)) > maximum) throw failure('EK_WEBHOOK_DELIVERY');
  return freezeData(result);
}
