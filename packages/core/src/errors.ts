// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { ErrorCode, KitErrorOptions } from './contracts.js';

const errorCodes = new Set<ErrorCode>([
  'EK_CONFIG_INVALID',
  'EK_CONFIG_MISSING',
  'EK_CONFIG_RELOAD_REJECTED',
  'EK_LIFECYCLE_STATE',
  'EK_PLUGIN_DUPLICATE',
  'EK_PLUGIN_DEPENDENCY',
  'EK_PLUGIN_FAILED',
  'EK_ABORTED',
  'EK_TIMEOUT',
  'EK_UNSUPPORTED_CAPABILITY',
  'EK_RESOURCE_CLOSED',
  'EK_DATABASE_CONNECT',
  'EK_DATABASE_QUERY',
  'EK_DATABASE_CONSTRAINT',
  'EK_DATABASE_CONFLICT',
  'EK_DATABASE_POOL_TIMEOUT',
  'EK_DATABASE_TRANSACTION',
  'EK_DATABASE_UNAVAILABLE',
  'EK_KV_CONFLICT',
  'EK_DOCUMENT_OPERATION',
  'EK_BACKEND_UNAVAILABLE',
  'EK_HTTP_VALIDATION',
  'EK_HTTP_NOT_FOUND',
  'EK_HTTP_UPSTREAM',
  'EK_HTTP_RATE_LIMIT',
  'EK_HTTP_TLS_CONFIG',
  'EK_HTTP_TLS_CERT',
  'EK_AUTH_REQUIRED',
  'EK_AUTH_INVALID',
  'EK_AUTH_FORBIDDEN',
  'EK_TENANT_UNVERIFIED',
  'EK_MFA_POLICY',
  'EK_MFA_ASSURANCE_REQUIRED',
  'EK_MFA_INVALID',
  'EK_MFA_EXPIRED',
  'EK_MFA_REPLAY',
  'EK_MFA_RATE_LIMIT',
  'EK_MFA_STORAGE',
  'EK_MFA_ALREADY_ENROLLED',
  'EK_MFA_ENROLLMENT_EXPIRED',
  'EK_MFA_CHALLENGE_EXPIRED',
  'EK_MFA_CREDENTIAL_CONFLICT',
  'EK_MFA_COUNTER_REGRESSION',
  'EK_TELEMETRY_CONFLICT',
  'EK_METER_SESSION',
  'EK_METER_CAPACITY',
  'EK_METER_EXPORT',
  'EK_HEALTH_NOT_READY',
  'EK_INTERNAL',
]);

/** EK-ERR-001: internal cause and message never enter external serialization. */
export class KitError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly details: Readonly<Record<string, string | number | boolean | null>>;

  constructor(options: KitErrorOptions) {
    if (
      !options ||
      !errorCodes.has(options.code) ||
      typeof options.message !== 'string' ||
      (options.retryable !== undefined && typeof options.retryable !== 'boolean')
    ) {
      throw new TypeError('Invalid framework error options');
    }
    if (
      Object.values(options.details ?? {}).some(
        (value) =>
          (!['string', 'number', 'boolean'].includes(typeof value) && value !== null) ||
          (typeof value === 'number' && !Number.isFinite(value)),
      )
    ) {
      throw new TypeError('Error details must contain finite primitive values');
    }
    super(options.message, { cause: options.cause });
    this.name = 'KitError';
    this.code = options.code;
    this.retryable = options.retryable ?? false;
    this.details = Object.freeze({ ...options.details });
    for (const key of ['code', 'retryable', 'details']) {
      Object.defineProperty(this, key, { enumerable: false, writable: false, configurable: false });
    }
  }

  /** Safe envelope contains no developer-controlled message, details or cause. */
  toSafeJSON(): { code: ErrorCode; message: string; requestId?: string } {
    return { code: this.code, message: 'The operation could not be completed safely.' };
  }

  /** JSON.stringify follows the same safe boundary. */
  toJSON(): { code: ErrorCode; message: string; requestId?: string } {
    return this.toSafeJSON();
  }
}
