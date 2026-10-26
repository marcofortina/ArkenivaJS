// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createValidationService, dataValidationPlugin } from '../../dist/index.js';
import type { ValidationService, ValidationResult } from '../../dist/index.js';

/** Compile positive and negative public contracts without executing malformed operations. */
export function publicContract(service: ValidationService, result: ValidationResult<string>) {
  const settings = { schemas: {}, policy: { maxConcurrent: 1, timeoutMs: 100 } };
  createValidationService(settings);
  dataValidationPlugin(settings);
  // @ts-expect-error Schemes must be explicitly declared.
  service.url('https://example.org', {});
  // @ts-expect-error FTP is outside this service's public protocol policy.
  service.url('ftp://example.org', { schemes: ['ftp:'] });
  // @ts-expect-error Unsupported identifier versions are not public API.
  service.uuid('invalid', 1);
  // @ts-expect-error Policies have no implicit unlimited defaults.
  dataValidationPlugin({ schemas: {} });
  if (result.valid) {
    const value: string = result.value;
    return value;
  }
  // @ts-expect-error Rejected results have no value to consume.
  return result.value;
}
