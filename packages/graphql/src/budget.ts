// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import {
  getArgumentValues,
  getDirectiveValues,
  getNamedType,
  getOperationAST,
  getVariableValues,
  GraphQLIncludeDirective,
  GraphQLSkipDirective,
  isCompositeType,
  isListType,
  isNonNullType,
  isObjectType,
  isInterfaceType,
  Kind,
  SchemaMetaFieldDef,
  TypeMetaFieldDef,
  TypeNameMetaFieldDef,
} from 'graphql';
import type { DocumentNode, GraphQLCompositeType, GraphQLSchema, SelectionSetNode } from 'graphql';
import type { CapturedSettings } from './policy.js';
import type { GraphqlRequestContext } from './contracts.js';
import { failure } from './policy.js';

/** Inspect the validated standard AST; parsing, coercion and execution remain upstream-owned. */
export function budget(
  schema: GraphQLSchema,
  document: DocumentNode,
  variables: Record<string, unknown> | undefined,
  context: GraphqlRequestContext,
  settings: CapturedSettings,
  method: string,
  authorizeIntrospection: () => void = () => {
    throw failure('EK_GQL_FORBIDDEN');
  },
) {
  const operation = getOperationAST(document, context.operationName);
  if (
    !operation ||
    operation.operation === 'subscription' ||
    (method === 'GET' && operation.operation !== 'query')
  )
    throw failure('EK_GQL_VALIDATION');
  const coercion = getVariableValues(schema, operation.variableDefinitions ?? [], variables ?? {}, {
    maxErrors: 1,
  });
  if (coercion.errors) throw failure('EK_GQL_VALIDATION');
  const values = coercion.coerced;
  const fragments = new Map(
    document.definitions
      .filter((node) => node.kind === Kind.FRAGMENT_DEFINITION)
      .map((node) => [node.name.value, node]),
  );
  const root = operation.operation === 'query' ? schema.getQueryType() : schema.getMutationType();
  if (!root) throw failure('EK_GQL_VALIDATION');
  const limits = settings.security.limits;
  let complexity = 0,
    aliases = 0;
  const walk = (
    selection: SelectionSetNode,
    type: GraphQLCompositeType,
    depth: number,
    multiplier: number,
    expanding: ReadonlySet<string>,
  ) => {
    if (depth > limits.maxDepth) throw failure('EK_GQL_COMPLEXITY');
    for (const node of selection.selections) {
      if (
        getDirectiveValues(GraphQLSkipDirective, node, values)?.if === true ||
        getDirectiveValues(GraphQLIncludeDirective, node, values)?.if === false
      )
        continue;
      if (node.kind === Kind.FRAGMENT_SPREAD) {
        const name = node.name.value,
          fragment = fragments.get(name);
        if (!fragment || expanding.has(name)) throw failure('EK_GQL_VALIDATION');
        const fragmentType = schema.getType(fragment.typeCondition.name.value);
        if (!fragmentType || !isCompositeType(fragmentType)) throw failure('EK_GQL_VALIDATION');
        walk(fragment.selectionSet, fragmentType, depth, multiplier, new Set([...expanding, name]));
      } else if (node.kind === Kind.INLINE_FRAGMENT) {
        const fragmentType = node.typeCondition
          ? schema.getType(node.typeCondition.name.value)
          : type;
        if (!fragmentType || !isCompositeType(fragmentType)) throw failure('EK_GQL_VALIDATION');
        walk(node.selectionSet, fragmentType, depth, multiplier, expanding);
      } else {
        const name = node.name.value;
        if (name === '__schema' || name === '__type') authorizeIntrospection();
        if (
          !context.auth &&
          !settings.security.auth.required &&
          (operation.operation !== 'query' ||
            (depth === 1 && !settings.security.auth.publicRootFields.includes(`Query.${name}`)))
        )
          throw failure('EK_GQL_AUTH');
        if (node.alias && ++aliases > limits.maxAliases) throw failure('EK_GQL_COMPLEXITY');
        const definition =
          name === '__typename'
            ? TypeNameMetaFieldDef
            : type === schema.getQueryType() && name === '__schema'
              ? SchemaMetaFieldDef
              : type === schema.getQueryType() && name === '__type'
                ? TypeMetaFieldDef
                : isObjectType(type) || isInterfaceType(type)
                  ? type.getFields()[name]
                  : undefined;
        if (!definition) throw failure('EK_GQL_VALIDATION');
        const args = getArgumentValues(definition, node, values);
        let output = definition.type,
          listMultiplier = 1;
        while (isNonNullType(output) || isListType(output)) {
          if (isListType(output)) {
            let cardinality = limits.maxCollectionItems;
            for (const key of ['first', 'last', 'limit', 'take', 'pageSize']) {
              if (args[key] === undefined || args[key] === null) continue;
              const count = args[key];
              if (
                typeof count !== 'number' ||
                !Number.isSafeInteger(count) ||
                count < 0 ||
                count > limits.maxCollectionItems
              )
                throw failure('EK_GQL_COMPLEXITY');
              cardinality = Math.min(cardinality, count);
            }
            listMultiplier *= Math.max(1, cardinality);
          }
          output = output.ofType;
        }
        complexity += multiplier * listMultiplier;
        if (!Number.isSafeInteger(complexity) || complexity > limits.maxComplexity)
          throw failure('EK_GQL_COMPLEXITY');
        const child = getNamedType(definition.type);
        if (node.selectionSet && isCompositeType(child))
          walk(node.selectionSet, child, depth + 1, multiplier * listMultiplier, expanding);
      }
    }
  };
  walk(operation.selectionSet, root, 1, 1, new Set());
  return { operation: operation.operation, complexity };
}
