// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { KafkaHeaders, KafkaPublishRequest } from './contracts.js';
import { toUSVString } from 'node:util';
import { array, bytes, failure, fields, text, topic } from './validation.js';

/** Independent header snapshots preserve duplicate order without trusting wire identity fields. */
export function headers(value: unknown): KafkaHeaders {
  const source = fields(value === undefined ? {} : value, undefined, true),
    output: Record<string, string | Buffer | null | readonly (string | Buffer | null)[]> =
      Object.create(null);
  let size = 0,
    count = 0;
  for (const [key, input] of Object.entries(source)) {
    text(key, 256);
    const copy = (entry: unknown): string | Buffer | null => {
      if (++count > 256) throw failure();
      size += Buffer.byteLength(key);
      let result: string | Buffer | null;
      if (entry === null) result = null;
      else if (typeof entry === 'string') {
        if (toUSVString(entry) !== entry) throw failure();
        result = entry;
        size += Buffer.byteLength(result);
      } else {
        result = bytes(entry, 16384);
        size += result.byteLength;
      }
      if (size > 16384) throw failure();
      return result;
    };
    if (Array.isArray(input)) {
      const values = array(input, 256);
      if (!values.length) throw failure();
      output[key] = Object.freeze(values.map(copy));
    } else output[key] = copy(input);
  }
  return Object.freeze(output);
}
/** Null and empty values remain distinct; tombstones require an explicit nonempty compaction key. */
export function publication(value: unknown, maximum: number): KafkaPublishRequest {
  const source = fields(value, ['cluster', 'topic', 'value', 'key', 'headers', 'messageId']);
  const key = source.key === undefined ? undefined : bytes(source.key, maximum);
  const body = source.value === null ? null : bytes(source.value, maximum);
  if (body === null && !key?.byteLength) throw failure();
  const metadata = headers(source.headers);
  if ((key?.byteLength ?? 0) + (body?.byteLength ?? 0) > maximum) throw failure();
  return Object.freeze({
    cluster: text(source.cluster, 128),
    topic: topic(source.topic),
    value: body,
    ...(key === undefined ? {} : { key }),
    headers: metadata,
    ...(source.messageId === undefined ? {} : { messageId: text(source.messageId, 256) }),
  });
}
