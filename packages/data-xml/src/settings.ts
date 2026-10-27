// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute, normalize } from 'node:path';
import type { DataXmlPluginSettings, XmlOptions } from './contracts.js';
import { failure, fields, integer } from './validation.js';
export const maximumBytes = 16 * 1024 * 1024;
export const optionKeys = [
  'maxBytes',
  'maxDepth',
  'maxAttributes',
  'forbidDtd',
  'externalEntities',
  'namespaceMode',
] as const;
export function options(input: XmlOptions | undefined, baseline?: ReturnType<typeof defaults>) {
  const value = fields(input === undefined ? {} : input, optionKeys),
    base = baseline ?? defaults();
  if (
    (value.forbidDtd !== undefined && value.forbidDtd !== true) ||
    (value.externalEntities !== undefined && value.externalEntities !== false) ||
    (value.namespaceMode !== undefined &&
      !['preserve', 'expanded'].includes(value.namespaceMode as string))
  )
    throw failure();
  return Object.freeze({
    maxBytes: integer(value.maxBytes === undefined ? base.maxBytes : value.maxBytes, maximumBytes),
    maxDepth: integer(value.maxDepth === undefined ? base.maxDepth : value.maxDepth, 256),
    maxAttributes: integer(
      value.maxAttributes === undefined ? base.maxAttributes : value.maxAttributes,
      65536,
    ),
    namespaceMode: (value.namespaceMode === undefined
      ? base.namespaceMode
      : value.namespaceMode) as 'preserve' | 'expanded',
    forbidDtd: true as const,
    externalEntities: false as const,
  });
}
function defaults() {
  return {
    maxBytes: 1024 * 1024,
    maxDepth: 64,
    maxAttributes: 4096,
    namespaceMode: 'preserve' as 'preserve' | 'expanded',
  };
}
/** Capture only trusted static settings; files and external backends are not accessed here. */
export function capture(input: DataXmlPluginSettings) {
  const value = fields(input, ['defaults', 'xsdSchemaFiles', 'policy']);
  const configured = options(value.defaults as XmlOptions),
    policy = fields(value.policy, [
      'maxConcurrent',
      'timeoutMs',
      'maxInputBytes',
      'maxOutputBytes',
    ]);
  if (value.defaults === undefined) throw failure();
  const maxConcurrent = integer(policy.maxConcurrent, 8),
    timeoutMs = integer(policy.timeoutMs, 30000),
    maxInputBytes = integer(
      policy.maxInputBytes === undefined ? configured.maxBytes : policy.maxInputBytes,
      maximumBytes,
    ),
    maxOutputBytes = integer(
      policy.maxOutputBytes === undefined ? configured.maxBytes : policy.maxOutputBytes,
      maximumBytes,
    );
  if (maxConcurrent * (maxInputBytes + maxOutputBytes) > 128 * 1024 * 1024) throw failure();
  const schemas = fields(value.xsdSchemaFiles === undefined ? {} : value.xsdSchemaFiles);
  if (Object.keys(schemas).length > 32) throw failure();
  for (const [id, path] of Object.entries(schemas)) {
    if (
      !/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/.test(id) ||
      typeof path !== 'string' ||
      path.length > 4096 ||
      path.includes('\0') ||
      !isAbsolute(path) ||
      normalize(path) !== path
    )
      throw failure();
  }
  return Object.freeze({
    defaults: configured,
    maxConcurrent,
    timeoutMs,
    maxInputBytes,
    maxOutputBytes,
    schemas: Object.freeze(schemas as Record<string, string>),
  });
}
export type Settings = ReturnType<typeof capture>;
