// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { toUSVString } from 'node:util';
import type { CapturedSettings } from './policy.js';
import { failure, record } from './policy.js';

export interface OperationInput {
  readonly query: string;
  readonly variables?: Record<string, unknown>;
  readonly operationName?: string;
}

/** Enforce transport-independent document and variable limits before the native parser runs. */
export function operationInput(
  input: unknown,
  limits: CapturedSettings['security']['limits'],
  method: string,
): OperationInput {
  let body: Record<string, unknown>;
  try {
    body = record(input, ['query', 'variables', 'operationName']);
  } catch {
    throw failure('EK_GQL_VALIDATION');
  }
  if (
    typeof body.query !== 'string' ||
    !body.query.trim() ||
    toUSVString(body.query) !== body.query ||
    (body.operationName !== undefined &&
      (typeof body.operationName !== 'string' ||
        !/^[_A-Za-z][_0-9A-Za-z]*$/.test(body.operationName)))
  )
    throw failure('EK_GQL_VALIDATION');
  if (Buffer.byteLength(body.query) > limits.maxDocumentBytes) throw failure('EK_GQL_INPUT_LIMIT');
  let variables = body.variables;
  if (method === 'GET' && typeof variables === 'string') {
    if (Buffer.byteLength(variables) > limits.maxVariablesBytes)
      throw failure('EK_GQL_INPUT_LIMIT');
    try {
      variables = JSON.parse(variables);
    } catch {
      throw failure('EK_GQL_VALIDATION');
    }
  }
  if (
    variables !== undefined &&
    (variables === null || typeof variables !== 'object' || Array.isArray(variables))
  )
    throw failure('EK_GQL_VALIDATION');
  if (
    variables !== undefined &&
    Buffer.byteLength(JSON.stringify(variables)) > limits.maxVariablesBytes
  )
    throw failure('EK_GQL_INPUT_LIMIT');
  return Object.freeze({
    query: body.query,
    ...(variables === undefined ? {} : { variables: variables as Record<string, unknown> }),
    ...(body.operationName === undefined ? {} : { operationName: body.operationName as string }),
  });
}
