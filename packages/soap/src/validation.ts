// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
const messages: Partial<Record<ErrorCode, string>> = {
  EK_SOAP_WSDL: 'The offline SOAP contract is invalid or exceeds its resource policy',
  EK_SOAP_SCHEMA: 'The SOAP message does not satisfy its approved protocol contract',
  EK_SOAP_FAULT: 'The remote SOAP operation returned a fault',
  EK_CONFIG_INVALID: 'The SOAP settings are invalid',
  EK_UNSUPPORTED_CAPABILITY: 'The SOAP contract requires an unsupported native capability',
  EK_TIMEOUT: 'The SOAP operation exceeded its deadline',
  EK_ABORTED: 'The SOAP operation was canceled',
  EK_RESOURCE_CLOSED: 'The SOAP resource is closed',
  EK_BACKEND_UNAVAILABLE: 'The native SOAP backend is unavailable',
};
export function failure(code: ErrorCode = 'EK_SOAP_WSDL'): KitError {
  return new KitError({ code, message: messages[code] ?? 'The SOAP operation failed' });
}
