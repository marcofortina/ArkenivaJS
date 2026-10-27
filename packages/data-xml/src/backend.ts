// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { SaxesParser } from 'saxes';
import type { SaxesTagNS } from 'saxes';
import { XMLParser, XMLBuilder } from 'fast-xml-parser';
import { toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { failure, fields } from './validation.js';
import type { options } from './settings.js';
import type { XmlDocument } from './contracts.js';

type Options = ReturnType<typeof options>;
interface Names {
  readonly name: string;
  readonly expanded: string;
  readonly attributes: ReadonlyMap<string, string>;
}
const dangerous = new Set(['__proto__', 'constructor', 'prototype']);
const clark = (uri: string, local: string) => (uri ? '{' + uri + '}' + local : local);

/** Decode only independently owned, bounded UTF-8 bytes; never invoke caller iterators or getters. */
export function inputText(input: unknown, maximum: number): string {
  try {
    if (typeof input === 'string') {
      if (toUSVString(input) !== input || Buffer.byteLength(input) > maximum)
        throw failure('EK_XML_SECURITY');
      return input;
    }
    if (!(input instanceof Uint8Array)) throw failure('EK_XML_PARSE');
    const native = Object.getPrototypeOf(Uint8Array.prototype) as object;
    const get = (key: string) =>
      Object.getOwnPropertyDescriptor(native, key)!.get!.call(input) as unknown;
    const buffer = get('buffer'),
      offset = get('byteOffset') as number,
      length = get('byteLength') as number;
    if (!(buffer instanceof ArrayBuffer) || length > maximum) throw failure('EK_XML_SECURITY');
    const owned = Buffer.from(new Uint8Array(buffer, offset, length));
    if (
      (owned[0] === 0xff && owned[1] === 0xfe) ||
      (owned[0] === 0xfe && owned[1] === 0xff) ||
      (owned[0] === 0 && owned[1] === 0 && owned[2] === 0xfe && owned[3] === 0xff)
    )
      throw failure('EK_UNSUPPORTED_CAPABILITY');
    return new TextDecoder('utf-8', { fatal: true }).decode(owned);
  } catch (error) {
    throw error instanceof KitError ? error : failure('EK_XML_PARSE');
  }
}

/** Native SAX validation rejects DTDs, undefined entities and namespace errors before tree allocation. */
export function preflight(
  text: string,
  policy: Options,
  rejectSchemaLocations = false,
): readonly Names[] {
  const parser = new SaxesParser({ xmlns: true }),
    names: Names[] = [];
  let depth = 0,
    attributes = 0,
    nodes = 0;
  const count = (value = 1) => {
    nodes += value;
    if (nodes > 100000) throw failure('EK_XML_SECURITY');
  };
  parser.on('text', () => count());
  parser.on('comment', () => count(2));
  parser.on('cdata', () => count(2));
  parser.on('error', () => {
    throw failure('EK_XML_PARSE');
  });
  parser.on('doctype', () => {
    throw failure('EK_XML_SECURITY');
  });
  parser.on('processinginstruction', () => {
    // The native ordered builder cannot preserve arbitrary instruction data faithfully.
    throw failure('EK_UNSUPPORTED_CAPABILITY');
  });
  parser.on('xmldecl', (declaration) => {
    if (
      declaration.version !== '1.0' ||
      (declaration.encoding !== undefined && !/^utf-8$/i.test(declaration.encoding))
    )
      throw failure('EK_UNSUPPORTED_CAPABILITY');
  });
  parser.on('opentag', (tag: SaxesTagNS) => {
    count();
    if (++depth > policy.maxDepth || dangerous.has(tag.local)) throw failure('EK_XML_SECURITY');
    const mapping = new Map<string, string>();
    for (const attribute of Object.values(tag.attributes)) {
      if (
        rejectSchemaLocations &&
        attribute.uri === 'http://www.w3.org/2001/XMLSchema-instance' &&
        ['schemaLocation', 'noNamespaceSchemaLocation'].includes(attribute.local)
      )
        throw failure('EK_XML_SECURITY');
      if (++attributes > policy.maxAttributes || dangerous.has(attribute.local))
        throw failure('EK_XML_SECURITY');
      mapping.set(
        attribute.name,
        attribute.name === 'xmlns' || attribute.prefix === 'xmlns'
          ? attribute.name
          : clark(attribute.uri, attribute.local),
      );
    }
    names.push({ name: tag.name, expanded: clark(tag.uri, tag.local), attributes: mapping });
  });
  parser.on('closetag', () => {
    depth--;
  });
  try {
    parser.write(text).close();
  } catch (error) {
    throw error instanceof KitError ? error : failure('EK_XML_PARSE');
  }
  return names;
}

/** Enumerate native-parsed XSD references without pretending to validate schema semantics. */
export function schemaDependencies(text: string, policy: Options): readonly string[] {
  preflight(text, policy);
  const parser = new SaxesParser({ xmlns: true }),
    references = new Set<string>();
  let root = false;
  parser.on('error', () => {
    throw failure('EK_XML_SCHEMA');
  });
  parser.on('opentag', (tag: SaxesTagNS) => {
    if (
      Object.values(tag.attributes).some(
        (attribute) =>
          attribute.uri === 'http://www.w3.org/XML/1998/namespace' && attribute.local === 'base',
      )
    )
      throw failure('EK_XML_SECURITY');
    if (!root) {
      root = true;
      if (tag.uri !== 'http://www.w3.org/2001/XMLSchema' || tag.local !== 'schema')
        throw failure('EK_XML_SCHEMA');
    }
    if (
      tag.uri === 'http://www.w3.org/2001/XMLSchema' &&
      ['include', 'import', 'redefine', 'override'].includes(tag.local)
    ) {
      const location = Object.values(tag.attributes).find(
        (attribute) => attribute.uri === '' && attribute.local === 'schemaLocation',
      )?.value;
      if (!location || location.length > 4096) throw failure('EK_XML_SCHEMA');
      references.add(location);
      if (references.size > 32) throw failure('EK_XML_SECURITY');
    }
  });
  try {
    parser.write(text).close();
  } catch (error) {
    throw error instanceof KitError ? error : failure('EK_XML_SCHEMA');
  }
  return Object.freeze([...references]);
}

/** The pinned native parser owns XML tokenization, entities and the ordered mixed-content tree. */
export function parseNative(input: Uint8Array | string, policy: Options): XmlDocument {
  const text = inputText(input, policy.maxBytes),
    names = preflight(text, policy);
  let index = 0;
  try {
    const parsed = new XMLParser({
      preserveOrder: true,
      ignoreAttributes: false,
      parseTagValue: false,
      parseAttributeValue: false,
      trimValues: false,
      ignoreDeclaration: true,
      cdataPropName: '#cdata',
      commentPropName: '#comment',
      maxNestedTags: policy.maxDepth,
      jPath: false,
      processEntities: {
        enabled: true,
        maxExpandedLength: policy.maxBytes,
        maxTotalExpansions: policy.maxBytes,
        maxEntityCount: 1,
      },
      onDangerousProperty: () => {
        throw failure('EK_XML_SECURITY');
      },
    }).parse(text) as Record<string, unknown>[];
    function convert(node: Record<string, unknown>): Readonly<Record<string, unknown>> {
      const result = Object.create(null) as Record<string, unknown>;
      const key = Object.keys(node).find((key) => key !== ':@');
      if (!key) throw failure('EK_XML_PARSE');
      const special = key.startsWith('#') || key.startsWith('?');
      const current = special ? undefined : names[index++];
      if (!special && current?.name !== key) throw failure('EK_XML_PARSE');
      const target = current && policy.namespaceMode === 'expanded' ? current.expanded : key;
      const content = node[key];
      result[target] = Array.isArray(content)
        ? Object.freeze(content.map((child) => convert(child as Record<string, unknown>)))
        : content;
      if (Object.hasOwn(node, ':@')) {
        const values = Object.create(null) as Record<string, unknown>;
        for (const [key, value] of Object.entries(node[':@'] as Record<string, unknown>)) {
          const name = key.slice(2),
            expanded = current?.attributes.get(name);
          values['@_' + (policy.namespaceMode === 'expanded' && expanded ? expanded : name)] =
            value;
        }
        result[':@'] = Object.freeze(values);
      }
      return Object.freeze(result);
    }
    const roots = parsed.filter((node) =>
      Object.keys(node).some((key) => key !== ':@' && !key.startsWith('#') && !key.startsWith('?')),
    );
    if (roots.length !== 1) throw failure('EK_XML_PARSE');
    const root = convert(roots[0]!);
    if (index !== names.length) throw failure('EK_XML_PARSE');
    return Object.freeze({ root });
  } catch (error) {
    throw error instanceof KitError ? error : failure('EK_XML_PARSE');
  }
}

/** Snapshot the explicit ordered native tree without evaluating accessors or coercing values. */
export function documentSnapshot(input: XmlDocument, policy: Options): XmlDocument {
  let bytes = 0,
    nodes = 0;
  const text = (value: unknown) => {
    if (typeof value !== 'string' || toUSVString(value) !== value) throw failure('EK_XML_SECURITY');
    bytes += Buffer.byteLength(value);
    if (bytes > policy.maxBytes) throw failure('EK_XML_SECURITY');
    return value;
  };
  function node(input: unknown, depth: number): Readonly<Record<string, unknown>> {
    if (depth > policy.maxDepth + 2 || ++nodes > 100000) throw failure('EK_XML_SECURITY');
    const source = fields(input),
      keys = Object.keys(source).filter((key) => key !== ':@');
    if (keys.length !== 1) throw failure('EK_XML_SECURITY');
    const key = text(keys[0]!),
      result = Object.create(null) as Record<string, unknown>,
      content = source[key];
    if (key === '#text') {
      if (Object.hasOwn(source, ':@')) throw failure('EK_XML_SECURITY');
      result[key] = text(content);
    } else {
      if (
        !Array.isArray(content) ||
        content.length > 100000 ||
        Reflect.ownKeys(content).length !== content.length + 1
      )
        throw failure('EK_XML_SECURITY');
      const children: Readonly<Record<string, unknown>>[] = [];
      for (let i = 0; i < content.length; i++) {
        const entry = Object.getOwnPropertyDescriptor(content, String(i));
        if (!entry || !Object.hasOwn(entry, 'value') || !entry.enumerable)
          throw failure('EK_XML_SECURITY');
        children.push(node(entry.value, depth + 1));
      }
      result[key] = Object.freeze(children);
      if (key === '#comment' || key === '#cdata') {
        if (
          children.length !== 1 ||
          Object.keys(children[0]!).join() !== '#text' ||
          Object.hasOwn(source, ':@')
        )
          throw failure('EK_XML_SECURITY');
        const value = children[0]!['#text'] as string;
        if (
          key === '#comment' ? value.includes('--') || value.endsWith('-') : value.includes(']]>')
        )
          throw failure('EK_XML_SECURITY');
      } else if (key.startsWith('#') || key.startsWith('?')) throw failure('EK_XML_SECURITY');
      if (Object.hasOwn(source, ':@')) {
        const attributes = fields(source[':@']),
          values = Object.create(null) as Record<string, string>;
        for (const [key, value] of Object.entries(attributes)) {
          if (!key.startsWith('@_') || key.length < 3) throw failure('EK_XML_SECURITY');
          text(key);
          values[key] = text(value);
        }
        result[':@'] = Object.freeze(values);
      }
    }
    return Object.freeze(result);
  }
  try {
    const root = node(fields(input, ['root']).root, 1);
    if (Object.keys(root).some((key) => key.startsWith('#') || key.startsWith('?')))
      throw failure('EK_XML_SECURITY');
    return Object.freeze({ root });
  } catch {
    throw failure('EK_XML_SECURITY');
  }
}

/** Resolve expanded names through retained declarations before invoking the native builder. */
export function stringifyNative(input: XmlDocument, policy: Options): string {
  const snapshot = documentSnapshot(input, policy);
  function lexical(
    node: Readonly<Record<string, unknown>>,
    inherited: ReadonlyMap<string, string>,
  ): Record<string, unknown> {
    const key = Object.keys(node).find((key) => key !== ':@')!;
    if (key.startsWith('#')) return node;
    const scope = new Map(inherited),
      attributes = node[':@'] as Record<string, string> | undefined;
    for (const [key, value] of Object.entries(attributes ?? {})) {
      if (key === '@_xmlns') scope.set('', value);
      else if (key.startsWith('@_xmlns:')) scope.set(key.slice(8), value);
    }
    const name = (value: string, attribute: boolean) => {
      if (policy.namespaceMode === 'preserve' || value === 'xmlns' || value.startsWith('xmlns:'))
        return value;
      if (!value.startsWith('{')) {
        if (value.includes(':') || (!attribute && scope.get(''))) throw failure('EK_XML_SECURITY');
        return value;
      }
      const at = value.lastIndexOf('}'),
        uri = value.slice(1, at),
        local = value.slice(at + 1);
      if (at < 2 || !local) throw failure('EK_XML_SECURITY');
      const prefix = [...scope].find(
        ([prefix, namespace]) => namespace === uri && (!attribute || prefix !== ''),
      )?.[0];
      if (prefix === undefined) throw failure('EK_XML_SECURITY');
      return prefix ? prefix + ':' + local : local;
    };
    const result = Object.create(null) as Record<string, unknown>;
    result[name(key, false)] = (node[key] as Readonly<Record<string, unknown>>[]).map((child) =>
      lexical(child, scope),
    );
    if (attributes) {
      const converted = Object.create(null) as Record<string, string>;
      for (const [key, value] of Object.entries(attributes))
        converted['@_' + name(key.slice(2), true)] = value;
      result[':@'] = converted;
    }
    return result;
  }
  try {
    const native = lexical(
      snapshot.root,
      new Map([['xml', 'http://www.w3.org/XML/1998/namespace']]),
    );
    const result = new XMLBuilder({
      preserveOrder: true,
      ignoreAttributes: false,
      cdataPropName: '#cdata',
      commentPropName: '#comment',
      processEntities: true,
      format: false,
    }).build([native]) as string;
    if (Buffer.byteLength(result) > policy.maxBytes) throw failure('EK_XML_SECURITY');
    // Verify real native roundtripping before returning any possibly injected or lossy output.
    if (JSON.stringify(parseNative(result, policy)) !== JSON.stringify(snapshot))
      throw failure('EK_XML_SECURITY');
    return result;
  } catch (error) {
    throw error instanceof KitError ? error : failure('EK_XML_PARSE');
  }
}
