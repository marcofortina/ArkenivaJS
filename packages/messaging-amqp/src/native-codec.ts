// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { failure } from './validation.js';
const require = createRequire(import.meta.url);
/** Narrow binding to the pinned native codec, used instead of a second AMQP encoder. */
interface Codec {
  encodeTable(buffer: Buffer, table: object, offset: number): number;
  decodeFields(bytes: Buffer): Record<string, unknown>;
}
export const nativeCodec = require(
  join(dirname(require.resolve('amqplib')), 'lib/codec.js'),
) as Codec;
/** Reject an unpatched installation before any value can silently lose fidelity. */
export function validateNativeCodec(codec: Codec = nativeCodec): void {
  const buffer = Buffer.alloc(64);
  try {
    const size = codec.encodeTable(
        buffer,
        { integer: { '!': 'int64', value: 9007199254740993n } },
        0,
      ),
      value = codec.decodeFields(buffer.subarray(4, size));
    if (Object.getPrototypeOf(value) !== null || value.integer !== 9007199254740993n)
      throw failure('EK_AMQP_CONFIG');
  } catch {
    throw failure('EK_AMQP_CONFIG');
  } finally {
    buffer.fill(0);
  }
}
let verified = false;
export function ensureNativeCodec(): void {
  if (!verified) {
    validateNativeCodec();
    verified = true;
  }
}
