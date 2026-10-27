// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { AmqpHeaders } from './contracts.js';
import { fields, array, text, failure } from './validation.js';
import { nativeCodec, ensureNativeCodec } from './native-codec.js';

const maximum = 16 * 1024;
interface Budget {
  bytes: number;
  entries: number;
  nodes: number;
  readonly parents: WeakSet<object>;
}
const budget = (): Budget => ({ bytes: 4, entries: 0, nodes: 0, parents: new WeakSet() });
function charge(state: Budget, bytes: number) {
  state.bytes += bytes;
  if (state.bytes > maximum || ++state.nodes > 4096) throw failure();
}
export function ownedBytes(value: unknown, maximum: number): Buffer {
  try {
    if (!(value instanceof Uint8Array)) throw failure();
    const prototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
    const get = (name: string): unknown =>
      Object.getOwnPropertyDescriptor(prototype, name)!.get!.call(value);
    const buffer = get('buffer') as ArrayBuffer,
      length = get('byteLength') as number,
      offset = get('byteOffset') as number;
    Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength')!.get!.call(buffer);
    if (length > maximum) throw failure();
    return Buffer.from(Buffer.from(buffer, offset, length));
  } catch {
    throw failure();
  }
}
function table(
  input: unknown,
  incoming: boolean,
  state: Budget,
  depth: number,
): Record<string, unknown> {
  const values = fields(input),
    result: Record<string, unknown> = Object.create(null);
  if (depth > 4 || state.parents.has(input as object)) throw failure();
  state.parents.add(input as object);
  try {
    for (const [name, value] of Object.entries(values)) {
      if (++state.entries > 128 || name === '!') throw failure();
      text(name, 255);
      charge(state, Buffer.byteLength(name) + 1);
      result[name] = field(value, incoming, state, depth);
    }
  } finally {
    state.parents.delete(input as object);
  }
  return Object.freeze(result);
}
function field(input: unknown, incoming: boolean, state: Budget, depth: number): unknown {
  charge(state, 1);
  if (input === null || typeof input === 'boolean') return input;
  if (typeof input === 'string') {
    if (input.length > maximum || Buffer.byteLength(input) > maximum) throw failure();
    const encoded = Buffer.from(input);
    try {
      if (encoded.toString('utf8') !== input) throw failure();
    } finally {
      encoded.fill(0);
    }
    charge(state, Buffer.byteLength(input));
    return input;
  }
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || (Number.isInteger(input) && !Number.isSafeInteger(input)))
      throw failure();
    return Object.is(input, -0) && !incoming
      ? Object.freeze({ '!': 'double', value: input })
      : input;
  }
  if (typeof input === 'bigint') {
    if (input < -(1n << 63n) || input > (1n << 63n) - 1n) throw failure();
    return incoming ? input : Object.freeze({ '!': 'int64', value: input });
  }
  if (input instanceof Uint8Array) {
    const value = ownedBytes(input, maximum - state.bytes);
    charge(state, value.length);
    return incoming ? new Uint8Array(value) : value;
  }
  if (input instanceof Date) {
    if (incoming || Reflect.ownKeys(input).length) throw failure();
    const milliseconds = Date.prototype.getTime.call(input);
    if (!Number.isSafeInteger(milliseconds) || milliseconds < 0 || milliseconds % 1000)
      throw failure();
    return Object.freeze({ '!': 'timestamp', value: milliseconds / 1000 });
  }
  if (!input || typeof input !== 'object') throw failure();
  if (incoming && Object.getPrototypeOf(input) === Object.prototype && Object.hasOwn(input, '!')) {
    const value = fields(input, ['!', 'value']);
    if (
      Object.keys(value).length !== 2 ||
      value['!'] !== 'timestamp' ||
      typeof value.value !== 'number' ||
      !Number.isSafeInteger(value.value) ||
      value.value < 0 ||
      value.value > 8640000000000
    )
      throw failure();
    return new Date(value.value * 1000);
  }
  if (depth >= 4 || state.parents.has(input)) throw failure();
  if (Array.isArray(input)) {
    state.parents.add(input);
    try {
      return Object.freeze(
        array(input, 256).map((value) => field(value, incoming, state, depth + 1)),
      );
    } finally {
      state.parents.delete(input);
    }
  }
  return table(input, incoming, state, depth + 1);
}
function nativeSize(table: Record<string, unknown>): number {
  const buffer = Buffer.alloc(maximum);
  try {
    const size = nativeCodec.encodeTable(buffer, table, 0);
    if (size > maximum || size < 4) throw failure();
    return size;
  } catch {
    throw failure();
  } finally {
    buffer.fill(0);
  }
}
/** Snapshot public values into the pinned native representations before any publication. */
export function outgoing(input: AmqpHeaders | undefined) {
  ensureNativeCodec();
  const native = table(input ?? {}, false, budget(), 0);
  return Object.freeze({ native, size: nativeSize(native) });
}
/** Copy native delivery metadata before its driver-owned lifetime ends. */
export function incoming(input: unknown): AmqpHeaders {
  ensureNativeCodec();
  const result = table(input ?? {}, true, budget(), 0) as AmqpHeaders;
  // Re-encoding through the same native codec enforces the complete encoded-size budget.
  outgoing(result);
  return result;
}
