// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { toUSVString } from 'node:util';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import canonicalize from 'canonicalize';
import { createScanner, SyntaxKind, ScanError, visit } from 'jsonc-parser';
import { freezeData } from '@arkenivajs/core/support';
import { jsonSnapshot } from './json.js';
import type { TenantRegistrySnapshotV1_1 } from './contracts.js';
import { registrySchema } from './registry-schema.js';
import { validateOperationSchemas } from './schemas.js';
import { registryFailure } from './errors.js';

const ajv = new Ajv2020({
  strict: true,
  allErrors: false,
  ownProperties: true,
  validateFormats: true,
});
addFormats.default(ajv);
const schema = ajv.compile<TenantRegistrySnapshotV1_1>(registrySchema);

/** Upstream lexical and parser APIs enforce finite nesting and unique decoded object keys. */
export function parseRegistryJson(text: string, maxBytes = 8388608): unknown {
  try {
    if (
      typeof text !== 'string' ||
      !Number.isSafeInteger(maxBytes) ||
      maxBytes <= 0 ||
      text.length > maxBytes ||
      Buffer.byteLength(text) > maxBytes ||
      toUSVString(text) !== text
    )
      throw registryFailure();
    const scanner = createScanner(text, false);
    let depth = 0,
      tokens = 0;
    for (let token = scanner.scan(); token !== SyntaxKind.EOF; token = scanner.scan()) {
      if (
        ++tokens > 8000000 ||
        scanner.getTokenError() !== ScanError.None ||
        token === SyntaxKind.LineCommentTrivia ||
        token === SyntaxKind.BlockCommentTrivia
      )
        throw registryFailure();
      if (token === SyntaxKind.OpenBraceToken || token === SyntaxKind.OpenBracketToken) {
        if (++depth > 64) throw registryFailure();
      }
      if (token === SyntaxKind.CloseBraceToken || token === SyntaxKind.CloseBracketToken) {
        if (--depth < 0) throw registryFailure();
      }
    }
    const keys: Set<string>[] = [];
    visit(
      text,
      {
        onObjectBegin: () => {
          keys.push(new Set());
        },
        onObjectProperty: (name) => {
          const current = keys.at(-1);
          if (!current || current.has(name)) throw registryFailure();
          current.add(name);
        },
        onObjectEnd: () => {
          keys.pop();
        },
        onError: () => {
          throw registryFailure();
        },
      },
      { disallowComments: true, allowTrailingComma: false, allowEmptyContent: false },
    );
    return JSON.parse(text) as unknown;
  } catch {
    throw registryFailure();
  }
}

/** Complete file snapshots and SQL content bodies share the same strict duplicate-aware parser. */
export function parseRegistry(text: string, maxBytes = 8388608): TenantRegistrySnapshotV1_1 {
  return validateRegistry(parseRegistryJson(text, maxBytes), maxBytes);
}

/** RFC8785 is implemented by the pinned upstream library; arrays retain their supplied order. */
export function registryContentChecksum(
  snapshot: Pick<
    TenantRegistrySnapshotV1_1,
    'schemaVersion' | 'operations' | 'implementations' | 'bindings'
  >,
): string {
  try {
    const content = canonicalize({
      schemaVersion: snapshot.schemaVersion,
      operations: snapshot.operations,
      implementations: snapshot.implementations,
      bindings: snapshot.bindings,
    });
    if (typeof content !== 'string') throw registryFailure();
    return 'sha256:' + createHash('sha256').update(content, 'utf8').digest('hex');
  } catch {
    throw registryFailure();
  }
}

/** Validate syntax, immutable content, shape and local referential integrity before publication. */
export function validateRegistry(input: unknown, maxBytes = 8388608): TenantRegistrySnapshotV1_1 {
  try {
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw registryFailure();
    const value = jsonSnapshot(input, maxBytes);
    if (!schema(value) || !value.activatedAt.endsWith('Z')) throw registryFailure();
    const operations = new Set<string>(),
      implementations = new Set<string>(),
      bindings = new Set<string>(),
      routes = new Set<string>();
    for (const operation of value.operations) {
      const parts = operation.path.slice('/api/'.length).split('/');
      const parameters = new Set<string>();
      for (const part of parts) {
        if (!part || part === '.' || part === '..') throw registryFailure();
        if (part.startsWith(':')) {
          if (!/^:[A-Za-z_][A-Za-z0-9_]*$/.test(part) || parameters.has(part))
            throw registryFailure();
          parameters.add(part);
        } else if (!/^[A-Za-z0-9._-]+$/.test(part)) throw registryFailure();
      }
      const route =
        operation.method + ' ' + parts.map((part) => (part.startsWith(':') ? ':' : part)).join('/');
      if (
        operations.has(operation.id) ||
        routes.has(route) ||
        [...operation.label].some((character) => {
          const code = character.codePointAt(0)!;
          return code <= 31 || (code >= 127 && code <= 159);
        })
      )
        throw registryFailure();
      operations.add(operation.id);
      routes.add(route);
    }
    validateOperationSchemas(value.operations);
    for (const implementation of value.implementations) {
      if (implementations.has(implementation.id)) throw registryFailure();
      implementations.add(implementation.id);
      if (
        implementation.kind === 'http' &&
        (implementation.upstreamPath.startsWith('//') ||
          implementation.upstreamPath.split('/').some((part) => part === '.' || part === '..'))
      )
        throw registryFailure();
    }
    for (const binding of value.bindings) {
      const key = JSON.stringify([binding.tenantId, binding.operationId]);
      if (
        bindings.has(key) ||
        !operations.has(binding.operationId) ||
        !implementations.has(binding.implementationId)
      )
        throw registryFailure();
      bindings.add(key);
    }
    if (registryContentChecksum(value) !== value.contentChecksum) throw registryFailure();
    return freezeData(value);
  } catch {
    throw registryFailure();
  }
}
