// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parseTree, getNodeValue, modify, applyEdits } from 'jsonc-parser';
import type { Node, ParseError } from 'jsonc-parser';
import { failure } from './validation.js';

/** Inspect a bounded upstream syntax tree before exposing a manifest's own data properties. */
export function manifest(text: string): Record<string, unknown> {
  if (Buffer.byteLength(text) > 1048576) throw failure();
  const errors: ParseError[] = [];
  const tree = parseTree(text, errors, { disallowComments: true, allowTrailingComma: false });
  if (!tree || tree.type !== 'object' || errors.length) throw failure();
  const queue: { node: Node; depth: number }[] = [{ node: tree, depth: 0 }];
  let count = 0;
  while (queue.length) {
    const { node, depth } = queue.pop()!;
    if (++count > 10000 || depth > 32) throw failure();
    if (node.type === 'object') {
      const seen = new Set<string>();
      for (const property of node.children ?? []) {
        const key: unknown = property.children?.[0]?.value;
        if (
          typeof key !== 'string' ||
          seen.has(key) ||
          ['__proto__', 'constructor', 'prototype'].includes(key)
        )
          throw failure();
        seen.add(key);
      }
    }
    for (const child of node.children ?? []) queue.push({ node: child, depth: depth + 1 });
  }
  const data: unknown = getNodeValue(tree);
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw failure();
  return data as Record<string, unknown>;
}
export function dependencyEdit(text: string, name: string, version: string): string {
  const data = manifest(text);
  for (const section of [
    'dependencies',
    'devDependencies',
    'peerDependencies',
    'optionalDependencies',
  ]) {
    const entries = data[section];
    if (entries === undefined) continue;
    if (!entries || typeof entries !== 'object' || Array.isArray(entries)) throw failure();
    const own = Object.getOwnPropertyDescriptor(entries, name)?.value;
    if (own !== undefined) {
      if (section === 'dependencies' && own === version) return text;
      throw failure('The selected dependency conflicts with the existing manifest');
    }
  }
  const result = applyEdits(
    text,
    modify(text, ['dependencies', name], version, {
      formattingOptions: {
        insertSpaces: !/^\t/m.test(text),
        tabSize: 2,
        eol: text.includes('\r\n') ? '\r\n' : '\n',
      },
    }),
  );
  manifest(result);
  return result;
}
