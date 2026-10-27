// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
import { SEMVER_PATTERN } from '@arkenivajs/core/support';

export const failure = (
  message = 'The project operation is invalid',
  code: ErrorCode = 'EK_CONFIG_INVALID',
  unknown = false,
) => new KitError({ code, message, ...(unknown ? { details: { outcome: 'unknown' } } : {}) });
export function fields(input: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure();
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    const property = Object.getOwnPropertyDescriptor(input, key)!;
    if (typeof key !== 'string' || !allowed.includes(key) || !('value' in property))
      throw failure();
    result[key] = property.value;
  }
  return result;
}
export function releaseVersion(input: unknown): string {
  if (typeof input !== 'string' || input.length > 128 || !new RegExp(SEMVER_PATTERN).test(input))
    throw failure('An exact framework version is required');
  return input;
}
export function projectName(input: unknown): string {
  if (
    typeof input !== 'string' ||
    !/^[a-z][a-z0-9-]{0,62}$/.test(input) ||
    /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])$/.test(input)
  )
    throw failure('Use a lowercase project name containing only letters, digits and hyphens');
  return input;
}
