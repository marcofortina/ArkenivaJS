// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import { GraphQLError } from 'graphql';
import type { ExecutionResult } from 'graphql';
import type { ErrorCode } from '@arkenivajs/core';
import { failure, record } from './policy.js';
import { encodeResult } from './encoding.js';

const codes = new Set([
  'EK_GQL_VALIDATION',
  'EK_GQL_INPUT_LIMIT',
  'EK_GQL_COMPLEXITY',
  'EK_GQL_AUTH',
  'EK_GQL_FORBIDDEN',
  'EK_GQL_EXECUTION',
  'EK_GQL_TIMEOUT',
  'EK_GQL_RESPONSE_LIMIT',
  'EK_GQL_SUBSCRIPTION',
  'EK_GQL_BACKPRESSURE',
]);
function property(value: unknown, name: string): unknown {
  if (!value || typeof value !== 'object' || types.isProxy(value)) return undefined;
  const field = Object.getOwnPropertyDescriptor(value, name);
  return field && 'value' in field ? field.value : undefined;
}

/** Native start errors bypass the normal formatter; only safe codes and bounded paths survive. */
export function subscriptionError(
  input: unknown,
  maximum: number,
  fallback: ErrorCode = 'EK_GQL_SUBSCRIPTION',
) {
  const raw = property(property(input, 'extensions'), 'code');
  const code = typeof raw === 'string' && codes.has(raw) ? (raw as ErrorCode) : fallback;
  const path = property(input, 'path');
  let captured: readonly (string | number)[] | undefined;
  if (Array.isArray(path) && !types.isProxy(path)) {
    if (path.length > maximum) throw failure('EK_GQL_RESPONSE_LIMIT');
    const parts: (string | number)[] = [];
    for (let index = 0; index < path.length; index++) {
      const value = property(path, String(index));
      if (typeof value !== 'string' && !(Number.isSafeInteger(value) && (value as number) >= 0))
        throw failure('EK_GQL_EXECUTION');
      parts.push(value as string | number);
    }
    captured = Object.freeze(parts);
  }
  return Object.freeze({
    message: failure(code).message,
    ...(captured ? { path: captured } : {}),
    extensions: Object.freeze({ code }),
  });
}

/** Materialize once under the byte cap so native JSON.stringify cannot revisit application values. */
export function sealSubscriptionResult(execution: ExecutionResult, maximum: number) {
  let fields: Record<string, unknown>;
  try {
    fields = record(execution, ['data', 'errors', 'extensions']);
  } catch {
    throw failure('EK_GQL_EXECUTION');
  }
  const errors = fields.errors;
  if (errors !== undefined && (!Array.isArray(errors) || types.isProxy(errors)))
    throw failure('EK_GQL_EXECUTION');
  if (Array.isArray(errors) && errors.length > maximum) throw failure('EK_GQL_RESPONSE_LIMIT');
  const prepared = {
    data: fields.data ?? null,
    ...(Array.isArray(errors) && errors.length
      ? {
          errors: errors.map((error: unknown) =>
            subscriptionError(error, maximum, 'EK_GQL_EXECUTION'),
          ),
        }
      : {}),
    ...(fields.extensions === undefined ? {} : { extensions: fields.extensions }),
  };
  const materialized = JSON.parse(encodeResult(prepared, maximum)) as Record<string, unknown>;
  const formattedErrors = Array.isArray(materialized.errors)
    ? Object.freeze(
        materialized.errors.map((error: unknown) => {
          const safe = subscriptionError(error, maximum, 'EK_GQL_EXECUTION');
          return Object.freeze(
            new GraphQLError(safe.message, {
              ...(safe.path ? { path: safe.path } : {}),
              extensions: safe.extensions,
            }),
          );
        }),
      )
    : undefined;
  for (const key of ['data', 'errors', 'extensions'])
    Object.defineProperty(execution, key, {
      value: key === 'errors' ? formattedErrors : materialized[key],
      enumerable: Object.hasOwn(materialized, key),
      writable: false,
      configurable: false,
    });
  Object.freeze(execution);
}
