// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { ErrorCode } from '@arkenivajs/core';
export const headerBytes = 16;
export const errorCodes: readonly ErrorCode[] = [
  'EK_BACKEND_UNAVAILABLE',
  'EK_SOAP_WSDL',
  'EK_SOAP_SCHEMA',
  'EK_SOAP_FAULT',
  'EK_UNSUPPORTED_CAPABILITY',
];
export interface ParserSettings {
  readonly source: string;
  readonly protocol: '1.1' | '1.2';
  readonly timeoutMs: number;
  readonly maxBytes: number;
}
