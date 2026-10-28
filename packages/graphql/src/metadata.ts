// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import {
  defaultFieldResolver,
  introspectionTypes,
  isObjectType,
  SchemaMetaFieldDef,
  TypeMetaFieldDef,
  TypeNameMetaFieldDef,
} from 'graphql';
import type { GraphQLField, GraphQLFieldResolver } from 'graphql';
import type { CapturedSettings } from './policy.js';
import type { Operation } from './operation.js';
import { authorizedField } from './fields.js';
import { failure } from './policy.js';

interface MetadataRequest {
  readonly scope: Operation;
  readonly settings: CapturedSettings;
  readonly authorizeIntrospection: () => void;
}
// Upstream metadata definitions are shared across schemas. Only owned request contexts dispatch policy.
const requests = new WeakMap<object, MetadataRequest>();
const bindings = new Map<GraphQLField<unknown, unknown>, GraphQLFieldResolver<unknown, unknown>>();

export function installMetadata() {
  if (bindings.size) {
    assertMetadata();
    return;
  }
  const fields = [
    SchemaMetaFieldDef,
    TypeMetaFieldDef,
    TypeNameMetaFieldDef,
    ...introspectionTypes.filter(isObjectType).flatMap((type) => Object.values(type.getFields())),
  ];
  for (const field of fields) {
    const original = field.resolve ?? defaultFieldResolver;
    const guarded: GraphQLFieldResolver<unknown, unknown> = (
      parent,
      args: Record<string, unknown>,
      context,
      info,
    ) => {
      const owned = context && typeof context === 'object' ? requests.get(context) : undefined;
      if (!owned) return original(parent, args, context, info);
      return authorizedField(owned.scope, owned.settings, parent, args, info, field.type, () => {
        if (field !== TypeNameMetaFieldDef) owned.authorizeIntrospection();
        return original(parent, args, context, info);
      });
    };
    field.resolve = guarded;
    bindings.set(field, guarded);
  }
}

/** Fail closed if trusted in-process instrumentation replaced an installed guard. */
export function assertMetadata() {
  for (const [field, resolver] of bindings)
    if (field.resolve !== resolver) throw failure('EK_GQL_CONFIG');
}

export function ownMetadata(context: object, request: MetadataRequest) {
  requests.set(context, request);
}

export function authorizeMetadata(context: object) {
  const request = requests.get(context);
  if (!request) throw failure('EK_GQL_FORBIDDEN');
  request.authorizeIntrospection();
}
