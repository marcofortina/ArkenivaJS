// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { dataJsonPlugin, JSON_CAPABILITY } from '@arkenivajs/data-json';
import type { DataJsonPluginSettings, JsonService, JsonMappingV1 } from '@arkenivajs/data-json';

/** A deployment-approved mapping is immutable and independent of incoming document contents. */
export function exampleSettings(): DataJsonPluginSettings {
  const mapping: JsonMappingV1 = {
    schemaVersion: '1.0.0',
    id: 'inventory.summary.v1',
    inputSchemaId: 'inventory.input.v1',
    outputSchemaId: 'inventory.output.v1',
    fields: {
      item: { op: 'copy', path: '/sku', required: true },
      label: {
        op: 'coalesce',
        args: [
          { op: 'copy', path: '/label' },
          { op: 'literal', value: 'Unnamed item' },
        ],
      },
      enabled: { op: 'to-boolean', value: { op: 'copy', path: '/enabled', required: true } },
      quantity: { op: 'to-number', value: { op: 'copy', path: '/quantity', required: true } },
    },
    limits: { maxDepth: 8, maxNodes: 64, maxArrayItems: 100, maxOutputBytes: 4096 },
  };
  return {
    defaults: { maxBytes: 8192, maxDepth: 16 },
    schemas: {
      'inventory.input.v1': {
        type: 'object',
        properties: {
          sku: { type: 'string' },
          label: { type: ['string', 'null'] },
          enabled: { type: 'string' },
          quantity: { type: 'string' },
        },
        required: ['sku', 'enabled', 'quantity'],
        additionalProperties: false,
      },
      'inventory.output.v1': {
        type: 'object',
        properties: {
          item: { type: 'string' },
          label: { type: 'string' },
          enabled: { type: 'boolean' },
          quantity: { type: 'number', minimum: 0 },
        },
        required: ['item', 'label', 'enabled', 'quantity'],
        additionalProperties: false,
      },
    },
    mappings: {
      ids: Object.freeze([mapping.id]),
      get: (id) => (id === mapping.id ? mapping : null),
    },
    policy: { maxConcurrent: 1, timeoutMs: 3000, maxInputBytes: 8192, maxOutputBytes: 16384 },
  };
}
export async function runJsonExample(): Promise<{
  valid: boolean;
  item: string;
  enabled: boolean;
  outputBytes: number;
}> {
  const app = await createApplication({
    service: { name: 'json-example', version: '0.1.0', environment: 'development' },
    plugins: [dataJsonPlugin(exampleSettings())],
  });
  try {
    await app.start();
    const json = app.resolve<JsonService>(JSON_CAPABILITY);
    const input = json.parse(
      '{"sku":"001","label":"Ελληνικά שלום","enabled":"true","quantity":"12.5"}',
    );
    const valid = json.validate(input, 'inventory.input.v1').valid;
    const output = json.transform(input, 'inventory.summary.v1') as Readonly<{
      item: string;
      enabled: boolean;
    }>;
    return {
      valid,
      item: output.item,
      enabled: output.enabled,
      outputBytes: Buffer.byteLength(json.stringify(output)),
    };
  } finally {
    await app.stop();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  try {
    console.log(JSON.stringify(await runJsonExample()));
  } catch {
    console.error('The JSON example failed');
    process.exitCode = 1;
  }
