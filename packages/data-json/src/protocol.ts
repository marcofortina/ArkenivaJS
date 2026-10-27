// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { ErrorCode } from '@arkenivajs/core';
import type { Limits } from './codec.js';
export const headerBytes = 16;
export const errorCodes: readonly ErrorCode[] = [
  'EK_BACKEND_UNAVAILABLE',
  'EK_JSON_PARSE',
  'EK_JSON_SCHEMA',
  'EK_JSON_TRANSFORM',
  'EK_CONFIG_INVALID',
  'EK_TIMEOUT',
  'EK_ABORTED',
];
export type Operation = 'parse' | 'stringify' | 'validate' | 'transform';
export interface Request {
  readonly operation: Operation;
  readonly text: string;
  readonly id?: string;
  readonly limits: Limits;
  readonly timeoutMs: number;
}
