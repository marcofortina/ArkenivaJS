// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parse, validate } from 'graphql';
import type { GraphQLSchema } from 'graphql';
import type { AuthService } from '@arkenivajs/core';
import type { GraphqlRequestContext } from './contracts.js';
import type { CapturedSettings } from './policy.js';
import { failure } from './policy.js';
import { operationInput } from './input.js';
import { budget } from './budget.js';

/** Preflight precedes Mercurius subscription parsing and never substitutes for delivery reauthorization. */
export function subscriptionDocument(
  input: unknown,
  schema: GraphQLSchema,
  settings: CapturedSettings,
  context: GraphqlRequestContext,
  authority: AuthService,
) {
  if (context.signal.aborted) throw failure('EK_GQL_TIMEOUT');
  if (!context.identity || !context.auth) throw failure('EK_GQL_AUTH');
  try {
    if (authority.tenantFrom(context.identity) !== context.auth) throw failure('EK_GQL_AUTH');
    if (settings.security.auth.required) {
      for (const scope of settings.security.auth.scopes ?? [])
        authority.requireScope(context.identity, scope);
      if (settings.security.auth.assurance)
        authority.requireAssurance(context.identity, settings.security.auth.assurance);
    }
  } catch {
    throw failure('EK_GQL_AUTH');
  }
  const captured = operationInput(input, settings.security.limits, 'WEBSOCKET');
  let document;
  try {
    document = parse(captured.query, { maxTokens: settings.security.limits.maxDocumentBytes });
    if (validate(schema, document, undefined, { maxErrors: 1 }).length)
      throw failure('EK_GQL_VALIDATION');
  } catch {
    throw failure('EK_GQL_VALIDATION');
  }
  const metadata = Object.freeze({
    requestId: context.requestId,
    signal: context.signal,
    identity: context.identity,
    auth: context.auth,
    ...(captured.operationName === undefined ? {} : { operationName: captured.operationName }),
  });
  const estimate = budget(schema, document, captured.variables, metadata, settings, 'WEBSOCKET');
  return Object.freeze({ input: captured, document, complexity: estimate.complexity });
}
