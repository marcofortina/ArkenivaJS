// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import {
  defaultFieldResolver,
  GraphQLError,
  isListType,
  isNonNullType,
  isObjectType,
  responsePathAsArray,
} from 'graphql';
import type { GraphQLSchema, GraphQLOutputType, GraphQLResolveInfo } from 'graphql';
import { KitError } from '@arkenivajs/core';
import type { CapturedSettings } from './policy.js';
import type { GraphqlFieldInfo } from './contracts.js';
import { failure } from './policy.js';
import type { Operation } from './operation.js';
import type { SubscriptionExecution } from './subscription-execution.js';

export function fieldInfo(info: GraphQLResolveInfo): GraphqlFieldInfo {
  return Object.freeze({
    parentType: info.parentType.name,
    fieldName: info.fieldName,
    operation: info.operation.operation,
    ...(info.operation.name ? { operationName: info.operation.name.value } : {}),
    path: Object.freeze(responsePathAsArray(info.path)),
  });
}

async function collection(
  input: unknown,
  type: GraphQLOutputType,
  maximum: number,
  check: () => void,
): Promise<unknown> {
  const value = await input;
  check();
  if (isNonNullType(type)) return collection(value, type.ofType, maximum, check);
  if (value == null || !isListType(type)) return value;
  // Materialize only bounded iterables; do not silently truncate an oversized success.
  if (typeof value !== 'object' || !(Symbol.iterator in value)) throw failure('EK_GQL_EXECUTION');
  const result: unknown[] = [];
  for (const item of value as Iterable<unknown>) {
    if (result.length === maximum) throw failure('EK_GQL_COMPLEXITY');
    result.push(await collection(item, type.ofType, maximum, check));
    check();
  }
  return result;
}

/** Shared policy applies to business and upstream metadata resolvers with their actual parent and path. */
export async function authorizedField(
  scope: Operation | undefined,
  settings: CapturedSettings,
  parent: unknown,
  args: Record<string, unknown>,
  info: GraphQLResolveInfo,
  output: GraphQLOutputType | undefined,
  execute: () => unknown | Promise<unknown>,
) {
  const began = scope?.observation?.startField();
  try {
    if (!scope) throw failure('EK_GQL_FORBIDDEN');
    scope.check();
    if (info.operation.operation === 'mutation' && info.path.prev === undefined)
      scope.mutationEpoch++;
    if (++scope.fields > scope.limits.maxFieldExecutions) throw failure('EK_GQL_COMPLEXITY');
    const metadata = fieldInfo(info);
    let authorized = false;
    try {
      authorized =
        (await scope.run(() =>
          settings.security.authorizeField(
            Object.freeze({
              context: scope.context,
              field: metadata,
              args,
              parent,
            }),
          ),
        )) === true;
    } catch {
      scope.check();
    }
    if (!authorized) throw failure('EK_GQL_FORBIDDEN');
    const value = await scope.run(execute);
    scope.check();
    const result =
      output === undefined
        ? value
        : await scope.run(() =>
            collection(value, output, scope.limits.maxCollectionItems, () => scope.check()),
          );
    scope.resolvedFields++;
    return result;
  } catch (error) {
    if (scope) scope.failed = true;
    const safe =
      error instanceof KitError &&
      ['EK_GQL_FORBIDDEN', 'EK_GQL_TIMEOUT', 'EK_GQL_COMPLEXITY'].includes(error.code)
        ? failure(error.code)
        : failure('EK_GQL_EXECUTION');
    throw new GraphQLError(safe.message, { extensions: { code: safe.code } });
  } finally {
    scope?.observation?.field(
      began,
      info.parentType.name.startsWith('__') || info.fieldName.startsWith('__'),
    );
  }
}

/** Install policy before the upstream executor can read either explicit or default fields. */
export function protectFields(
  schema: GraphQLSchema,
  settings: CapturedSettings,
  scopes: Pick<WeakMap<object, Operation>, 'get'>,
  subscriptions?: Pick<WeakMap<object, SubscriptionExecution>, 'get'>,
) {
  for (const type of Object.values(schema.getTypeMap())) {
    if (!isObjectType(type) || type.name.startsWith('__')) continue;
    for (const [name, field] of Object.entries(type.getFields())) {
      const configured = settings.resolvers[type.name]?.[name];
      const resolve = typeof configured === 'function' ? configured : configured?.resolve;
      if (type === schema.getSubscriptionType()) {
        field.subscribe = (parent, args: Record<string, unknown>, context: object, info) => {
          const execution = subscriptions?.get(context);
          if (!execution || !configured || typeof configured === 'function') {
            const safe = failure('EK_GQL_FORBIDDEN');
            throw new GraphQLError(safe.message, { extensions: { code: safe.code } });
          }
          return execution.openSource(parent, args, info, configured.subscribe);
        };
      }
      const native = field.resolve ?? defaultFieldResolver;
      field.resolve = (parent, args: Record<string, unknown>, context: object, info) => {
        const scope = scopes.get(context);
        return authorizedField(scope, settings, parent, args, info, field.type, () =>
          resolve
            ? resolve(parent, args, scope!.context, fieldInfo(info))
            : native(
                parent,
                args,
                native === defaultFieldResolver ? scope!.context : context,
                info,
              ),
        );
      };
    }
  }
}
