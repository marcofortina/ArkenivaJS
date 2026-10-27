// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute } from 'node:path';
import type { DataXlsxPluginSettings, XlsxOptions } from './contracts.js';
import { fields, integer, text, failure } from './validation.js';

const optionNames = [
  'maxSheets',
  'maxRowsPerSheet',
  'maxCells',
  'maxUncompressedBytes',
  'formulaPolicy',
  'readMode',
  'temporaryStorage',
] as const;
export function options(input: XlsxOptions = {}) {
  const value = fields(input, optionNames),
    formulaPolicy = value.formulaPolicy ?? 'reject',
    readMode = value.readMode ?? 'stream';
  if (
    !['reject', 'preserve', 'strip'].includes(formulaPolicy as string) ||
    !['stream', 'random-access'].includes(readMode as string)
  )
    throw failure();
  let temporaryStorage:
    Readonly<{ directory: string; maxBytes: number; cleanup: 'always' }> | undefined;
  if (value.temporaryStorage !== undefined) {
    const storage = fields(value.temporaryStorage, ['directory', 'maxBytes', 'cleanup']),
      directory = text(storage.directory, 4096);
    if (!isAbsolute(directory) || storage.cleanup !== 'always') throw failure();
    temporaryStorage = Object.freeze({
      directory,
      maxBytes: integer(storage.maxBytes, 512 * 1024 * 1024),
      cleanup: 'always',
    });
  }
  return Object.freeze({
    maxSheets: integer(value.maxSheets ?? 16, 256),
    maxRowsPerSheet: integer(value.maxRowsPerSheet ?? 100000, 1048576),
    maxCells: integer(value.maxCells ?? 1000000, 10000000),
    maxUncompressedBytes: integer(
      value.maxUncompressedBytes ?? 64 * 1024 * 1024,
      512 * 1024 * 1024,
    ),
    formulaPolicy: formulaPolicy as 'reject' | 'preserve' | 'strip',
    readMode: readMode as 'stream' | 'random-access',
    ...(temporaryStorage ? { temporaryStorage } : {}),
  });
}
export type Options = ReturnType<typeof options>;
export function capture(input: DataXlsxPluginSettings) {
  try {
    const value = fields(input, ['defaults', 'policy']),
      policy = fields(value.policy, [
        'maxConcurrent',
        'timeoutMs',
        'maxInputBytes',
        'maxOutputBytes',
      ]);
    if (value.defaults === undefined) throw failure();
    const defaults = options(value.defaults as XlsxOptions);
    return Object.freeze({
      defaults,
      maxConcurrent: integer(policy.maxConcurrent, 8),
      timeoutMs: integer(policy.timeoutMs, 120000),
      maxInputBytes: integer(policy.maxInputBytes ?? 16 * 1024 * 1024, 256 * 1024 * 1024),
      maxOutputBytes: integer(policy.maxOutputBytes ?? 32 * 1024 * 1024, 256 * 1024 * 1024),
    });
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export type Settings = ReturnType<typeof capture>;
