// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';

const maximumBytes = 1048576;
const invalid = () =>
  new KitError({ code: 'EK_MFA_INVALID', message: 'Invalid WebAuthn response' });

/** Serialize only bounded JSON data, without invoking getters, toJSON or custom prototypes. */
function serialize(input: unknown): string {
  let bytes = 0,
    nodes = 0;
  const ancestors = new Set<object>();
  const count = (value: string) => {
    bytes += Buffer.byteLength(value);
    if (bytes > maximumBytes) throw invalid();
    return value;
  };
  const quoted = (value: string) => {
    if (value.length > maximumBytes) throw invalid();
    return count(JSON.stringify(value));
  };
  const encode = (value: unknown, depth: number): string => {
    if (++nodes > 4096 || depth > 16) throw invalid();
    if (value === null || typeof value === 'boolean') return count(JSON.stringify(value));
    if (typeof value === 'string') return quoted(value);
    if (typeof value === 'number' && Number.isFinite(value)) return count(JSON.stringify(value));
    if (!value || typeof value !== 'object' || ancestors.has(value)) throw invalid();
    const array = Array.isArray(value),
      prototype = Object.getPrototypeOf(value);
    if (
      array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null
    )
      throw invalid();
    const fields = Object.getOwnPropertyDescriptors(value),
      keys = Reflect.ownKeys(fields);
    if (keys.length > 4097) throw invalid();
    ancestors.add(value);
    try {
      if (array) {
        const length = fields.length?.value;
        if (
          !Number.isSafeInteger(length) ||
          length < 0 ||
          length > 4096 ||
          keys.length !== length + 1
        )
          throw invalid();
        count('[]');
        const parts: string[] = [];
        for (let index = 0; index < length; index++) {
          const field = fields[String(index)];
          if (!field || !('value' in field) || !field.enumerable) throw invalid();
          if (index > 0) count(',');
          parts.push(encode(field.value, depth + 1));
        }
        return '[' + parts.join(',') + ']';
      }
      count('{}');
      const parts: string[] = [];
      for (const key of keys) {
        if (typeof key !== 'string' || ['__proto__', 'constructor', 'prototype'].includes(key))
          throw invalid();
        const field = fields[key]!;
        if (!('value' in field) || !field.enumerable) throw invalid();
        // Browser JSON objects may carry an omitted optional property as undefined.
        if (field.value === undefined) continue;
        if (parts.length > 0) count(',');
        const name = quoted(key);
        count(':');
        parts.push(name + ':' + encode(field.value, depth + 1));
      }
      return '{' + parts.join(',') + '}';
    } finally {
      ancestors.delete(value);
    }
  };
  return encode(input, 0);
}

function record(value: unknown): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
}

function base64(value: unknown, maximum: number, exact?: number): string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > Math.ceil((maximum * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    throw invalid();
  const decoded = Buffer.from(value, 'base64url');
  if (
    decoded.length > maximum ||
    (exact !== undefined && decoded.length !== exact) ||
    decoded.toString('base64url') !== value
  )
    throw invalid();
  return value;
}

/** Unverified routing material only; the caller must still verify the complete upstream proof. */
export function readUnverifiedResponse(input: unknown, registration: boolean) {
  try {
    const serialized = serialize(input);
    const value: unknown = JSON.parse(serialized);
    record(value);
    record(value.response);
    const credentialId = base64(value.id, 1024);
    if (value.rawId !== credentialId || value.type !== 'public-key') throw invalid();
    const encoded = base64(value.response.clientDataJSON, 16384);
    const client: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(encoded, 'base64url')),
    );
    record(client);
    const challenge = base64(client.challenge, 32, 32);
    const userHandle = value.response.userHandle;
    if (!registration && userHandle !== undefined && userHandle !== null)
      base64(userHandle, 32, 32);
    return Object.freeze({
      serialized,
      credentialId,
      challenge,
      ...(registration || userHandle === undefined
        ? {}
        : { userHandle: userHandle as string | null }),
    });
  } catch {
    throw invalid();
  }
}
