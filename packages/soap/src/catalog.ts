// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { SaxesParser } from 'saxes';
import type { WSDL } from 'soap';
import type { ContractAssets } from './assets.js';
import type { SoapServiceProfile } from './contracts.js';
import { inspectXml } from './xml.js';
import { failure, hasControls } from './validation.js';

const wsdlNamespace = 'http://schemas.xmlsoap.org/wsdl/',
  xsdNamespace = 'http://www.w3.org/2001/XMLSchema',
  soap11 = 'http://schemas.xmlsoap.org/wsdl/soap/',
  soap12 = 'http://schemas.xmlsoap.org/wsdl/soap12/';
export interface QualifiedName {
  readonly local: string;
  readonly uri: string;
}
export interface Binding {
  readonly name: string;
  readonly service: string;
  readonly port: string;
  readonly action: string;
  readonly input: QualifiedName;
  readonly output: QualifiedName;
  readonly outputAliases?: readonly string[];
}
function property(input: unknown, name: string): unknown {
  if (!input || typeof input !== 'object') throw failure();
  const descriptor = Object.getOwnPropertyDescriptor(input, name);
  if (!descriptor || !('value' in descriptor)) throw failure();
  return descriptor.value;
}
function entries(input: unknown): [string, unknown][] {
  if (!input || typeof input !== 'object') throw failure();
  const keys = Object.keys(input);
  if (keys.length > 128) throw failure();
  return keys.map((name) => [name, property(input, name)]);
}
function text(input: unknown): string {
  if (typeof input !== 'string' || !input || input.length > 2048 || hasControls(input))
    throw failure();
  return input;
}
/** Inventory namespace-sensitive declarations; native SOAP remains the contract compiler. */
export function protocols(assets: ContractAssets): ReadonlyMap<string, '1.1' | '1.2'> {
  const result = new Map<string, '1.1' | '1.2'>(),
    declarations = new Set<string>();
  for (const document of assets.documents) {
    inspectXml(document.source);
    const parser = new SaxesParser({ xmlns: true });
    let depth = 0,
      binding: string | undefined;
    parser.on('opentag', (tag) => {
      depth++;
      const permitted = ['binding', 'operation', 'fault'].includes(tag.local)
        ? [wsdlNamespace, soap11, soap12]
        : [
              'definitions',
              'types',
              'message',
              'part',
              'portType',
              'service',
              'port',
              'input',
              'output',
            ].includes(tag.local)
          ? [wsdlNamespace]
          : [
                'schema',
                'element',
                'complexType',
                'simpleType',
                'sequence',
                'choice',
                'all',
                'attribute',
                'complexContent',
                'simpleContent',
                'restriction',
                'extension',
              ].includes(tag.local)
            ? [xsdNamespace]
            : undefined;
      if (permitted && !permitted.includes(tag.uri)) throw failure();
      if (
        depth === 2 &&
        tag.uri === wsdlNamespace &&
        ['message', 'portType', 'binding', 'service'].includes(tag.local)
      ) {
        const name = Object.values(tag.attributes).find(
          (attribute) => attribute.name === 'name',
        )?.value;
        if (!name || declarations.has(tag.local + ':' + name))
          throw failure('EK_UNSUPPORTED_CAPABILITY');
        declarations.add(tag.local + ':' + name);
        if (tag.local === 'binding') binding = name;
      }
      if (depth === 3 && binding && tag.local === 'binding') {
        if (![soap11, soap12].includes(tag.uri) || result.has(binding)) throw failure();
        result.set(binding, tag.uri === soap11 ? '1.1' : '1.2');
      }
      if (
        [soap11, soap12].includes(tag.uri) &&
        tag.local === 'body' &&
        Object.values(tag.attributes).some(
          (attribute) => attribute.name === 'use' && attribute.value !== 'literal',
        )
      )
        throw failure('EK_UNSUPPORTED_CAPABILITY');
      if ([wsdlNamespace, xsdNamespace].includes(tag.uri)) {
        for (const attribute of Object.values(tag.attributes)) {
          if (
            ![
              'type',
              'base',
              'ref',
              'element',
              'message',
              'binding',
              'itemType',
              'memberTypes',
              'substitutionGroup',
            ].includes(attribute.local)
          )
            continue;
          if (attribute.prefix) throw failure();
          for (const value of attribute.value.trim().split(/\s+/)) {
            const parts = value.split(':');
            if (
              parts.length > 2 ||
              parts.some((part) => !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(part)) ||
              (parts.length === 2 && !parser.resolve(parts[0]!))
            )
              throw failure();
          }
        }
      }
    });
    parser.on('closetag', () => {
      if (depth-- === 2) binding = undefined;
    });
    parser.write(document.source).close();
  }
  return result;
}
export function catalog(
  native: WSDL,
  assets: ContractAssets,
  profile: SoapServiceProfile,
): readonly Binding[] {
  const versions = protocols(assets),
    definitions: unknown = native.definitions,
    bindings = entries(property(definitions, 'bindings')),
    result: Binding[] = [];
  for (const [service, value] of entries(property(definitions, 'services'))) {
    for (const [port, definition] of entries(property(value, 'ports'))) {
      const binding = property(definition, 'binding'),
        name = bindings.find(([, value]) => value === binding)?.[0];
      if (!name || versions.get(name) !== profile.protocol) continue;
      for (const [name, method] of entries(property(binding, 'methods'))) {
        if (!profile.allowedOperations.includes(name)) continue;
        if (result.some((entry) => entry.name === name)) throw failure('EK_UNSUPPORTED_CAPABILITY');
        const style = property(method, 'style') || 'document';
        if (style !== 'document' && style !== 'rpc') throw failure('EK_UNSUPPORTED_CAPABILITY');
        const input = property(method, 'input'),
          output = property(method, 'output');
        if (!input || !output) throw failure('EK_UNSUPPORTED_CAPABILITY');
        const namespace = text(property(definitions, '$targetNamespace'));
        const request = Object.freeze({
          local: style === 'rpc' ? name : text(property(input, '$name')),
          uri: style === 'rpc' ? namespace : text(property(input, 'targetNamespace')),
        });
        const response = Object.freeze({
          local: text(property(output, '$name')),
          uri: style === 'rpc' ? namespace : text(property(output, 'targetNamespace')),
        });
        const action = property(method, 'soapAction');
        if (typeof action !== 'string' || action.length > 2048 || hasControls(action))
          throw failure();
        result.push(
          Object.freeze({
            name,
            service,
            port,
            input: request,
            output: response,
            action,
            ...(style === 'rpc'
              ? {
                  outputAliases: Object.freeze(
                    [
                      ...new Set([
                        response.local.replace(/(?:Out(?:put)?|Response)$/, ''),
                        name + 'Response',
                        name + 'Out',
                        name + 'Output',
                      ]),
                    ].filter(Boolean),
                  ),
                }
              : {}),
          }),
        );
      }
    }
  }
  if (result.length !== profile.allowedOperations.length) throw failure();
  return Object.freeze(result);
}
