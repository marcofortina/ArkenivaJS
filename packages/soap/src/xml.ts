// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { toUSVString } from 'node:util';
import { Client } from 'soap';
import { SaxesParser } from 'saxes';
import { failure } from './validation.js';
const wsdl = 'http://schemas.xmlsoap.org/wsdl/',
  xsd = 'http://www.w3.org/2001/XMLSchema';
const dangerous = new Set(['__proto__', 'prototype', 'constructor']);
const reserved = new Set([
  ...Object.getOwnPropertyNames(Client.prototype),
  ...Object.getOwnPropertyNames(Object.prototype),
  'then',
  'catch',
  'finally',
  'wsdl',
  'httpClient',
  'soapHeaders',
  'httpHeaders',
  'bodyAttributes',
  'endpoint',
  'security',
  'lastRequest',
  'lastMessage',
  'lastEndpoint',
  'lastRequestHeaders',
  'lastResponse',
  'lastResponseHeaders',
  'lastResponseAttachments',
  'lastElapsedTime',
  'native',
  'close',
  'call',
  '_events',
  '_eventsCount',
  '_maxListeners',
  'normalizeNames',
  'overridePromiseSuffix',
  'SOAPAction',
  'streamAllowed',
  'returnSaxStream',
]);
for (
  let prototype: object | null = Client.prototype;
  prototype;
  prototype = Object.getPrototypeOf(prototype)
)
  for (const name of Object.getOwnPropertyNames(prototype)) reserved.add(name);
export interface XmlInventory {
  readonly root: Readonly<{ local: string; uri: string }>;
  readonly imports: readonly string[];
  readonly elements: number;
  readonly attributes: number;
  readonly maximumDepth: number;
}

/** A vetted native SAX parser admits bounded XML before the separate native SOAP contract compiler. */
export function inspectXml(source: string, maxBytes = 1048576): XmlInventory {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1 ||
    maxBytes > 8388608 ||
    typeof source !== 'string' ||
    source.length > maxBytes ||
    Buffer.byteLength(source) > maxBytes ||
    toUSVString(source) !== source
  )
    throw failure();
  const parser = new SaxesParser({ xmlns: true });
  let root: { local: string; uri: string } | undefined,
    depth = 0,
    maximumDepth = 0,
    elements = 0,
    attributes = 0;
  const imports: string[] = [],
    operations = new Set<string>();
  parser.on('doctype', () => {
    throw failure();
  });
  parser.on('processinginstruction', () => {
    throw failure('EK_UNSUPPORTED_CAPABILITY');
  });
  parser.on('xmldecl', (value) => {
    if (value.version !== '1.0' || (value.encoding && !/^utf-8$/i.test(value.encoding)))
      throw failure('EK_UNSUPPORTED_CAPABILITY');
  });
  parser.on('opentag', (tag) => {
    if (++depth > 64 || ++elements > 20000 || dangerous.has(tag.local) || dangerous.has(tag.prefix))
      throw failure();
    maximumDepth = Math.max(maximumDepth, depth);
    root ??= { local: tag.local, uri: tag.uri };
    const values = Object.values(tag.attributes);
    if (tag.uri === wsdl && tag.local === 'operation') {
      const name = values.find((value) => value.local === 'name')?.value;
      if (name) operations.add(name);
    }
    attributes += values.length;
    if (attributes > 4096) throw failure();
    for (const attribute of values) {
      if (
        dangerous.has(attribute.local) ||
        dangerous.has(attribute.prefix) ||
        attribute.name === 'xml:base'
      )
        throw failure();
      if (
        ['name', 'type', 'base', 'ref', 'element', 'message', 'binding'].includes(
          attribute.local,
        ) &&
        dangerous.has(attribute.value.trim().split(':').at(-1)!)
      )
        throw failure();
      if (
        attribute.uri === 'http://www.w3.org/2000/xmlns/' &&
        dangerous.has(attribute.value.trim())
      )
        throw failure();
      if (
        tag.uri === wsdl &&
        ['operation', 'service', 'port'].includes(tag.local) &&
        attribute.name === 'name' &&
        (!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(attribute.value) || reserved.has(attribute.value))
      )
        throw failure();
    }
    if (['import', 'include', 'redefine', 'override'].includes(tag.local)) {
      if (tag.uri !== wsdl && tag.uri !== xsd) throw failure();
      // Match both attributes accepted by the native include implementation.
      for (const attribute of values.filter((value) =>
        ['location', 'schemaLocation'].includes(value.local),
      )) {
        const reference = attribute.value;
        if (!reference || reference.length > 4096) throw failure();
        if (!imports.includes(reference)) {
          if (imports.length >= 32) throw failure();
          imports.push(reference);
        }
      }
    }
  });
  parser.on('closetag', () => {
    depth--;
  });
  parser.on('error', () => {
    throw failure();
  });
  try {
    parser.write(source).close();
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'code' in error &&
      error.code === 'EK_UNSUPPORTED_CAPABILITY'
    )
      throw error;
    throw failure();
  }
  if (!root || depth !== 0) throw failure();
  if ([...operations].some((name) => name.endsWith('Async') && operations.has(name.slice(0, -5))))
    throw failure();
  return Object.freeze({
    root: Object.freeze(root),
    imports: Object.freeze(imports),
    elements,
    attributes,
    maximumDepth,
  });
}
export function inspectWsdl(source: string, maxBytes = 1048576): XmlInventory {
  const result = inspectXml(source, maxBytes);
  if (result.root.local !== 'definitions' || result.root.uri !== wsdl) throw failure();
  return result;
}
