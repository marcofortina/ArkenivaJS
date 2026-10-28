// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { buildSchema, isObjectType, validateSchema } from 'graphql';
import type { CapturedSettings } from './policy.js';
import { failure } from './policy.js';

/** Validate SDL and all application coordinates before any route or listener exists. */
export function compileSchema(settings: CapturedSettings) {
  try {
    const schema = buildSchema(settings.schema);
    if (
      validateSchema(schema).length ||
      !schema.getQueryType() ||
      !Object.keys(schema.getQueryType()!.getFields()).length
    )
      throw failure('EK_GQL_SCHEMA');
    for (const [typeName, fields] of Object.entries(settings.resolvers)) {
      const type = schema.getType(typeName);
      if (!isObjectType(type) || typeName.startsWith('__')) throw failure('EK_GQL_SCHEMA');
      for (const [name, resolver] of Object.entries(fields)) {
        if (
          !type.getFields()[name] ||
          (typeof resolver !== 'function' && type !== schema.getSubscriptionType()) ||
          (typeof resolver === 'function' && type === schema.getSubscriptionType())
        )
          throw failure('EK_GQL_SCHEMA');
      }
    }
    for (const [typeName, fields] of Object.entries(settings.loaders ?? {})) {
      const type = schema.getType(typeName);
      if (!isObjectType(type) || typeName.startsWith('__') || type === schema.getSubscriptionType())
        throw failure('EK_GQL_SCHEMA');
      for (const name of Object.keys(fields)) {
        if (!type.getFields()[name] || settings.resolvers[typeName]?.[name])
          throw failure('EK_GQL_SCHEMA');
      }
    }
    if (!settings.security.auth.required) {
      const query = schema.getQueryType()!;
      if (
        query.name !== 'Query' ||
        settings.security.auth.publicRootFields.some(
          (coordinate) => !query.getFields()[coordinate.slice('Query.'.length)],
        )
      )
        throw failure('EK_GQL_SCHEMA');
    }
    return schema;
  } catch {
    throw failure('EK_GQL_SCHEMA');
  }
}
