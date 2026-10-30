// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
import { compileSchema, copyData, freezeData } from '@arkenivajs/core/support';
import type { UploadPluginSettings, UploadPolicy, UploadRoute } from './contracts.js';

export const failure = (code: ErrorCode = 'EK_UPLOAD_CONFIG') =>
  new KitError({ code, message: 'The multipart upload could not complete' });

/** Reject accessors, symbols and unexpected properties without executing application getters. */
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
export function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw failure();
  return value as number;
}
export function text(value: unknown, maximum: number): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > maximum ||
    Buffer.byteLength(value) > maximum ||
    /[\p{Cc}\p{Cf}]/u.test(value) ||
    toUSVString(value) !== value
  )
    throw failure();
  return value;
}
function list(input: unknown, maximum: number, allowEmpty = false): readonly unknown[] {
  if (
    !Array.isArray(input) ||
    (input.length < 1 && !allowEmpty) ||
    input.length > maximum ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure();
  const result: unknown[] = [];
  for (let index = 0; index < input.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !('value' in descriptor)) throw failure();
    result.push(descriptor.value);
  }
  return result;
}
function policy(input: unknown): UploadPolicy {
  const value = fields(input, [
    'maxRequestBytes',
    'maxFileBytes',
    'maxFiles',
    'maxFields',
    'maxFieldBytes',
    'maxParts',
    'allowedMediaTypes',
  ]);
  const media = list(value.allowedMediaTypes, 64).map((item) => {
    const type = text(item, 127);
    if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(type)) throw failure();
    return type;
  });
  if (new Set(media).size !== media.length) throw failure();
  return Object.freeze({
    // Explicit byte ceilings bound streaming work without limiting files to an in-memory size.
    maxRequestBytes: integer(value.maxRequestBytes, Number.MAX_SAFE_INTEGER),
    maxFileBytes: integer(value.maxFileBytes, Number.MAX_SAFE_INTEGER),
    maxFiles: integer(value.maxFiles, 256),
    maxFields: integer(value.maxFields, 256),
    maxFieldBytes: integer(value.maxFieldBytes, 65536),
    maxParts: integer(value.maxParts, 512),
    allowedMediaTypes: Object.freeze(media),
  });
}
/** Snapshot every route before a listener, parser or application handler can be activated. */
export function capture(input: UploadPluginSettings): readonly UploadRoute[] {
  try {
    const routes = list(fields(input, ['routes']).routes, 64).map((item): UploadRoute => {
      const value = fields(item, ['path', 'method', 'policy', 'auth', 'responseSchema', 'handler']);
      const path = text(value.path, 1024);
      if (
        !/^\/(?:[A-Za-z0-9._~:-]+\/)*[A-Za-z0-9._~:-]*$/.test(path) ||
        path.includes('//') ||
        path.split('/').some((segment) => segment === '.' || segment === '..') ||
        ['/livez', '/readyz'].includes(path) ||
        !['POST', 'PUT'].includes(value.method as string) ||
        typeof value.handler !== 'function'
      )
        throw failure();
      const auth = fields(value.auth === undefined ? { required: true } : value.auth, [
        'required',
        'scopes',
        'reason',
      ]);
      if (typeof auth.required !== 'boolean') throw failure();
      if (
        (auth.required && auth.reason !== undefined) ||
        (!auth.required && auth.scopes !== undefined)
      )
        throw failure();
      const capturedAuth = auth.required
        ? Object.freeze({
            required: true as const,
            ...(auth.scopes === undefined
              ? {}
              : {
                  scopes: Object.freeze(
                    list(auth.scopes, 64, true).map((scope) => text(scope, 256)),
                  ),
                }),
          })
        : Object.freeze({ required: false as const, reason: text(auth.reason, 1024) });
      let nodes = 0,
        schemaBytes = 0;
      const inspect = (schema: unknown, depth: number): void => {
        schemaBytes += 2 + (typeof schema === 'string' ? Buffer.byteLength(schema) : 8);
        if (++nodes > 4096 || depth > 32 || schemaBytes > 65536) throw failure();
        if (schema && typeof schema === 'object') {
          if (
            !Array.isArray(schema) &&
            ![null, Object.prototype].includes(Object.getPrototypeOf(schema))
          )
            throw failure();
          for (const name of Reflect.ownKeys(schema)) {
            if (name === 'length' && Array.isArray(schema)) continue;
            schemaBytes += typeof name === 'string' ? Buffer.byteLength(name) + 3 : 0;
            if (schemaBytes > 65536) throw failure();
            const descriptor = Object.getOwnPropertyDescriptor(schema, name)!;
            if (typeof name !== 'string' || !('value' in descriptor)) throw failure();
            inspect(descriptor.value, depth + 1);
          }
        } else if (typeof schema === 'string' && schema.length > 65536) throw failure();
      };
      inspect(value.responseSchema, 0);
      const schema = freezeData(copyData(value.responseSchema));
      if (
        !schema ||
        typeof schema !== 'object' ||
        Array.isArray(schema) ||
        Buffer.byteLength(JSON.stringify(schema)) > 65536
      )
        throw failure();
      compileSchema(schema);
      return Object.freeze({
        path,
        method: value.method as UploadRoute['method'],
        policy: policy(value.policy),
        auth: capturedAuth,
        responseSchema: schema,
        handler: value.handler as UploadRoute['handler'],
      });
    });
    if (
      new Set(
        routes.map(
          (route) => route.method + ':' + route.path.replace(/:[A-Za-z0-9_]+/g, ':parameter'),
        ),
      ).size !== routes.length
    )
      throw failure();
    return Object.freeze(routes);
  } catch {
    throw failure();
  }
}
