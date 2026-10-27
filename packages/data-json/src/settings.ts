// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { DataJsonPluginSettings, JsonMappingRegistry, JsonOptions } from './contracts.js';
import { options, snapshot } from './codec.js';
import { captureMappings } from './mappings.js';
import { failure, integer, record } from './validation.js';

/** Capture static owned settings without starting workers, listeners or asynchronous providers. */
export function capture(input: DataJsonPluginSettings) {
  const value = record(input, ['defaults', 'schemas', 'mappings', 'policy']);
  if (value.defaults === undefined || value.schemas === undefined || value.mappings === undefined)
    throw failure();
  const defaults = options(value.defaults as JsonOptions);
  const policy = record(value.policy, [
    'maxConcurrent',
    'timeoutMs',
    'maxInputBytes',
    'maxOutputBytes',
  ]);
  if (policy.maxConcurrent === undefined || policy.timeoutMs === undefined) throw failure();
  const maxConcurrent = integer(policy.maxConcurrent, 1, 4),
    timeoutMs = integer(policy.timeoutMs, 1000, 30000),
    maxInputBytes = integer(policy.maxInputBytes, defaults.maxBytes, 8388608),
    maxOutputBytes = integer(policy.maxOutputBytes, defaults.maxBytes, 8388608);
  if (maxConcurrent * (maxInputBytes + maxOutputBytes) > 64 * 1024 * 1024) throw failure();
  const schemas = record(
    snapshot(value.schemas, { maxBytes: 1048576, maxDepth: 64, indentSpaces: 0 }),
  );
  if (Object.keys(schemas).length > 128) throw failure('EK_JSON_SCHEMA');
  const mappings = captureMappings(value.mappings as JsonMappingRegistry);
  return Object.freeze({
    defaults,
    maxConcurrent,
    timeoutMs,
    maxInputBytes,
    maxOutputBytes,
    schemas: Object.freeze(schemas) as Readonly<Record<string, object>>,
    mappings,
  });
}
export type Settings = ReturnType<typeof capture>;
