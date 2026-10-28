// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { FastifyInstance } from 'fastify';
import type { MercuriusLoaders } from 'mercurius';
import type { GraphQLResolveInfo } from 'graphql';
import { isObjectType } from 'graphql';
import type { CapturedSettings } from './policy.js';
import type { GraphqlBatchLoadRequest } from './contracts.js';
import type { Operation } from './operation.js';
import { fieldInfo } from './fields.js';
import { failure } from './policy.js';

interface Entry {
  readonly coordinate: string;
  readonly request: GraphqlBatchLoadRequest;
}
interface FieldCache {
  epoch: number;
  nextParent: number;
  readonly objects: WeakMap<object, number>;
  readonly primitives: Map<unknown, number>;
  readonly results: Map<string, Promise<unknown>>;
}
interface RequestState {
  nextToken: number;
  readonly entries: Map<number, Entry>;
  readonly fields: Map<string, FieldCache>;
}

/** Use Mercurius scheduling with inert correlation tokens, never serialized application parents. */
export function installLoaders(
  server: FastifyInstance,
  settings: CapturedSettings,
  scopes: WeakMap<object, Operation>,
  observed: () => void,
) {
  if (!settings.loaders) return;
  const states = new WeakMap<Operation, RequestState>();
  const stateFor = (scope: Operation): RequestState => {
    let state = states.get(scope);
    if (!state) {
      state = { nextToken: 0, entries: new Map(), fields: new Map() };
      states.set(scope, state);
    }
    return state;
  };
  const native: MercuriusLoaders<object> = Object.create(null);
  for (const [typeName, fields] of Object.entries(settings.loaders)) {
    const definitions: MercuriusLoaders<object>[string] = Object.create(null);
    native[typeName] = definitions;
    for (const [name, definition] of Object.entries(fields)) {
      const coordinate = `${typeName}.${name}`;
      // The pinned native scheduler supports maxBatchSize even though its wrapper types omit it.
      const opts = { cache: false, maxBatchSize: definition.maxBatchSize! };
      definitions[name] = {
        opts,
        async loader(queries: readonly { obj: { token: number } }[], context: object) {
          const scope = scopes.get(context);
          if (!scope) throw failure('EK_GQL_FORBIDDEN');
          scope.check();
          if (!queries.length || queries.length > opts.maxBatchSize)
            throw failure('EK_GQL_EXECUTION');
          const state = stateFor(scope);
          const requests = queries.map((query) => {
            const entry = state.entries.get(query.obj.token);
            if (!entry || entry.coordinate !== coordinate) throw failure('EK_GQL_EXECUTION');
            return entry.request;
          });
          try {
            const results = await scope.run(() => {
              observed();
              scope.observation?.loader(requests.length);
              scope.loaderBatches++;
              scope.loaderItems += requests.length;
              return definition.load(Object.freeze(requests), scope.context);
            });
            if (!Array.isArray(results) || results.length !== queries.length)
              throw failure('EK_GQL_EXECUTION');
            return results;
          } finally {
            for (const query of queries) state.entries.delete(query.obj.token);
          }
        },
      };
    }
  }
  server.graphql.defineLoaders(native);
  for (const [typeName, fields] of Object.entries(settings.loaders)) {
    const type = server.graphql.schema.getType(typeName);
    if (!isObjectType(type)) throw failure('EK_GQL_SCHEMA');
    for (const [name, definition] of Object.entries(fields)) {
      const field = type.getFields()[name],
        resolve = field?.resolve;
      if (!field || !resolve) throw failure('EK_GQL_SCHEMA');
      const coordinate = `${typeName}.${name}`;
      field.resolve = (
        parent: unknown,
        args: Record<string, unknown>,
        context: object,
        info: GraphQLResolveInfo,
      ) => {
        const scope = scopes.get(context);
        if (!scope) throw failure('EK_GQL_FORBIDDEN');
        scope.check();
        const state = stateFor(scope);
        let cache = state.fields.get(coordinate);
        if (!cache || cache.epoch !== scope.mutationEpoch) {
          cache = {
            epoch: scope.mutationEpoch,
            nextParent: 0,
            objects: new WeakMap(),
            primitives: new Map(),
            results: new Map(),
          };
          state.fields.set(coordinate, cache);
        }
        const objects =
          parent !== null && (typeof parent === 'object' || typeof parent === 'function');
        let parentId = objects ? cache.objects.get(parent as object) : cache.primitives.get(parent);
        if (parentId === undefined) {
          parentId = ++cache.nextParent;
          if (objects) cache.objects.set(parent as object, parentId);
          else cache.primitives.set(parent, parentId);
        }
        // Coerced GraphQL argument keys follow schema order; no application parent property is read.
        const key = `${parentId}:${JSON.stringify(args)}`;
        if (definition.cache) {
          const cached = cache.results.get(key);
          if (cached) return cached;
        }
        const token = ++state.nextToken;
        state.entries.set(token, {
          coordinate,
          request: Object.freeze({ parent, args, info: fieldInfo(info) }),
        });
        const result = Promise.resolve().then(() =>
          resolve(Object.freeze({ token }), Object.freeze({}), context, info),
        );
        if (definition.cache) cache.results.set(key, result);
        return result;
      };
    }
  }
}
