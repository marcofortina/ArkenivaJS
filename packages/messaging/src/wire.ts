// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { MessageEnvelope } from '@arkenivajs/core';
import { compileSchema, copyData, freezeData } from '@arkenivajs/core/support';

export const MAX_MESSAGE_BYTES = 1_048_576;
export interface WireMessage {
  readonly schemaVersion: 1;
  readonly messageId: string;
  readonly topic: string;
  readonly payload: unknown;
  readonly correlationId?: string;
}
const correlationPattern = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}(?![\s\S])/;
const identityPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/;
const schema = {
  type: 'object',
  additionalProperties: false,
  required: ['schemaVersion', 'messageId', 'topic', 'payload'],
  properties: {
    schemaVersion: { const: 1 },
    messageId: {
      type: 'string',
      pattern: identityPattern.source,
    },
    topic: { type: 'string', minLength: 1, maxLength: 256 },
    payload: { $ref: '#/$defs/value' },
    correlationId: { type: 'string', pattern: correlationPattern.source },
  },
  $defs: {
    value: {
      anyOf: [
        { type: 'null' },
        { type: 'boolean' },
        { type: 'number' },
        { type: 'string' },
        { type: 'array', maxItems: 10000, items: { $ref: '#/$defs/value' } },
        { type: 'object', maxProperties: 10000, additionalProperties: { $ref: '#/$defs/value' } },
      ],
    },
  },
};
const validate = compileSchema(schema);

export function messageTopic(value: string): string {
  if (
    typeof value !== 'string' ||
    value.length > 256 ||
    !/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*(?![\s\S])/.test(value)
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Messaging topics require bounded literal subject tokens',
    });
  return value;
}
export function messageCorrelation(value: string | undefined): string | undefined {
  if (value !== undefined && (typeof value !== 'string' || !correlationPattern.test(value)))
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid message correlation identifier',
    });
  return value;
}

/** Reject executable, cyclic and oversized values before cloning or stringification allocates a wire buffer. */
function bounded(value: unknown): void {
  const ancestors = new Set<object>();
  let nodes = 0,
    bytes = 0;
  const charge = (size: number) => {
    if ((bytes += size) > MAX_MESSAGE_BYTES)
      throw new Error('Message JSON exceeds its pre-serialization byte bound');
  };
  const visit = (entry: unknown, depth: number) => {
    charge(1);
    if (
      ++nodes > 50000 ||
      depth > 64 ||
      entry === undefined ||
      ['function', 'symbol', 'bigint'].includes(typeof entry) ||
      (typeof entry === 'number' && !Number.isFinite(entry))
    )
      throw new Error('Message JSON exceeds its structural bound');
    if (typeof entry === 'string') charge(Buffer.byteLength(entry));
    if (!entry || typeof entry !== 'object') return;
    if (
      ancestors.has(entry) ||
      Object.getOwnPropertySymbols(entry).length ||
      (Array.isArray(entry) && entry.length > 10000)
    )
      throw new Error('Message JSON requires bounded acyclic plain data');
    if (Array.isArray(entry))
      for (let index = 0; index < entry.length; index++)
        if (!Object.hasOwn(entry, index)) throw new Error('Message arrays must be dense');
    const keys = Object.getOwnPropertyNames(entry);
    if (keys.length > 10001) throw new Error('Message JSON has too many fields');
    ancestors.add(entry);
    try {
      for (const key of keys) {
        if (Array.isArray(entry) && key === 'length') continue;
        if (Array.isArray(entry) && !/^(0|[1-9]\d*)(?![\s\S])/.test(key))
          throw new Error('Message arrays cannot contain named properties');
        if (!Array.isArray(entry)) charge(Buffer.byteLength(key));
        const descriptor = Object.getOwnPropertyDescriptor(entry, key);
        if (!descriptor || !('value' in descriptor))
          throw new Error('Message JSON cannot execute an accessor');
        visit(descriptor.value, depth + 1);
      }
    } finally {
      ancestors.delete(entry);
    }
  };
  visit(value, 0);
}

export function encodeMessage(message: WireMessage): Uint8Array {
  try {
    bounded(message);
    const captured = copyData(message);
    if (!validate(captured)) throw new Error('Message envelope does not satisfy its JSON schema');
    messageTopic(captured.topic);
    if (captured.correlationId !== undefined) messageCorrelation(captured.correlationId);
    const text = JSON.stringify(captured);
    if (Buffer.byteLength(text) > MAX_MESSAGE_BYTES)
      throw new Error('Message envelope exceeds its byte bound');
    return Buffer.from(text);
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Message requires bounded schema-checked JSON',
      cause,
    });
  }
}

/** Raw wire fields never construct tenant authority; unknown envelope fields, including tenant, are rejected. */
export function decodeMessage(bytes: Uint8Array, topic: string): MessageEnvelope<unknown> {
  try {
    if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_MESSAGE_BYTES)
      throw new Error('Message envelope exceeds its byte bound');
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    bounded(parsed);
    const captured = copyData(parsed);
    if (!validate(captured)) throw new Error('Message envelope does not satisfy its JSON schema');
    const message = captured as unknown as WireMessage;
    if (message.topic !== topic)
      throw new Error('Message envelope topic does not match its authorized subject');
    messageTopic(message.topic);
    messageCorrelation(message.correlationId);
    return freezeData({
      messageId: message.messageId,
      topic: message.topic,
      payload: message.payload,
      ...(message.correlationId === undefined ? {} : { correlationId: message.correlationId }),
    });
  } catch (cause) {
    throw new KitError({
      code: 'EK_BACKEND_UNAVAILABLE',
      message: 'Invalid untrusted message envelope',
      cause,
    });
  }
}
