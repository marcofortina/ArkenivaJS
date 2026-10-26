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
  'EK_SAML_CONFIGURATION',
  'EK_SAML_SIGNATURE',
  'EK_SAML_REPLAY',
  'EK_SAML_ASSERTION',
  'EK_LDAP_CONNECT',
  'EK_LDAP_BIND',
  'EK_LDAP_FILTER',
  'EK_LDAP_SEARCH',
  'EK_SCIM_BAD_REQUEST',
  'EK_SCIM_CONFLICT',
  'EK_SCIM_PRECONDITION',
  'EK_SCIM_UNAUTHORIZED',
  'EK_APIKEY_INVALID',
  'EK_APIKEY_EXPIRED',
  'EK_APIKEY_REVOKED',
  'EK_APIKEY_STORE',
  'EK_SESSION_EXPIRED',
  'EK_SESSION_REVOKED',
  'EK_SESSION_INVALID',
  'EK_SESSION_STORE',
  'EK_PASSWORD_POLICY',
  'EK_PASSWORD_INVALID',
  'EK_PASSWORD_RESET',
  'EK_PASSWORD_KDF',
  'EK_OAUTH_STATE',
  'EK_OAUTH_EXCHANGE',
  'EK_OAUTH_PROVIDER',
  'EK_OAUTH_POLICY',
  'EK_MTLS_INVALID_PEER',
  'EK_MTLS_CONFIGURATION',
  'EK_MTLS_HANDSHAKE',
  'EK_CRYPTO_AUTH_FAILED',
  'EK_CRYPTO_KEY_UNAVAILABLE',
  'EK_CRYPTO_FORMAT',
  'EK_MAGICLINK_INVALID',
  'EK_MAGICLINK_EXPIRED',
  'EK_MAGICLINK_REPLAY',
  'EK_HTTP_CSRF',
  'EK_HTTP_SECURITY_POLICY',
  'EK_X509_PARSE',
  'EK_X509_UNTRUSTED',
  'EK_X509_EXPIRED',
  'EK_MAIL_CONFIG',
  'EK_MAIL_SEND',
  'EK_MAIL_REJECTED',
  'EK_SFTP_HOSTKEY',
  'EK_SFTP_TRANSFER',
  'EK_SSH_FORBIDDEN',
  'EK_SOAP_WSDL',
  'EK_SOAP_FAULT',
  'EK_SOAP_SCHEMA',
  'EK_GRPC_STATUS',
  'EK_GRPC_DEADLINE',
  'EK_GRPC_AUTH',
  'EK_REALTIME_AUTH',
  'EK_REALTIME_BACKPRESSURE',
  'EK_REALTIME_CLOSED',
  'EK_WEBHOOK_SIGNATURE',
  'EK_WEBHOOK_REPLAY',
  'EK_WEBHOOK_DELIVERY',
  'EK_CSV_PARSE',
  'EK_CSV_LIMIT',
  'EK_CSV_SCHEMA',
  'EK_XLSX_FORMAT',
  'EK_XLSX_LIMIT',
  'EK_XLSX_UNSUPPORTED',
  'EK_XML_PARSE',
  'EK_XML_SCHEMA',
  'EK_XML_SECURITY',
  'EK_JSON_PARSE',
  'EK_JSON_SCHEMA',
  'EK_JSON_TRANSFORM',
  'EK_PDF_PARSE',
  'EK_PDF_SIGNED',
  'EK_PDF_LIMIT',
  'EK_CODE_UNSUPPORTED',
  'EK_CODE_DECODE',
  'EK_CODE_LIMIT',
  'EK_ARCHIVE_CORRUPT',
  'EK_ARCHIVE_LIMIT',
  'EK_ARCHIVE_PATH',
  'EK_TIME_INVALID',
  'EK_TIME_AMBIGUOUS',
  'EK_TIME_ZONE',
  'EK_IDENTIFIER_INVALID',
  'EK_VALIDATION_INVALID',
  'EK_VALIDATION_POLICY',
  'EK_EID_FEDERATION',
  'EK_EID_ASSURANCE',
  'EK_EID_PROFILE',
  'EK_HTTP_TLS_CONFIG',
  'EK_HTTP_TLS_CERT',
  'EK_HTTP_LISTEN',
  'EK_SOCKET_CONFIG',
  'EK_SOCKET_BIND',
  'EK_SOCKET_STATE',
  'EK_SOCKET_CLOSED',
  'EK_SOCKET_CAPACITY',
  'EK_SOCKET_IO',
  'EK_SOCKET_TLS_HANDSHAKE',
  'EK_SOCKET_DATAGRAM',
  'EK_UPLOAD_CONFIG',
  'EK_UPLOAD_LIMIT',
  'EK_UPLOAD_MEDIA_TYPE',
  'EK_UPLOAD_TRUNCATED',
  'EK_UPLOAD_STREAM',
  'EK_AMQP_CONFIG',
  'EK_AMQP_CONNECT',
  'EK_AMQP_PUBLISH',
  'EK_AMQP_CONSUME',
  'EK_AMQP_ACK_STATE',
  'EK_KAFKA_CONFIG',
  'EK_KAFKA_CONNECT',
  'EK_KAFKA_PUBLISH',
  'EK_KAFKA_CONSUME',
  'EK_KAFKA_OFFSET',
  'EK_KAFKA_REBALANCE',
  'EK_DNS_CONFIG',
  'EK_DNS_NOT_FOUND',
  'EK_DNS_TEMPORARY',
  'EK_DNS_TIMEOUT',
  'EK_PROXY_CONFIG',
  'EK_PROXY_POLICY',
  'EK_PROXY_UPSTREAM',
  'EK_PROXY_TIMEOUT',
  'EK_PROXY_BODY_LIMIT',
  'EK_GQL_CONFIG',
  'EK_GQL_SCHEMA',
  'EK_GQL_VALIDATION',
  'EK_GQL_INPUT_LIMIT',
  'EK_GQL_COMPLEXITY',
  'EK_GQL_AUTH',
  'EK_GQL_FORBIDDEN',
  'EK_GQL_EXECUTION',
  'EK_GQL_TIMEOUT',
  'EK_GQL_RESPONSE_LIMIT',
  'EK_GQL_SUBSCRIPTION',
  'EK_GQL_BACKPRESSURE',
  'EK_TROUTE_CONFIG',
  'EK_TROUTE_REGISTRY',
  'EK_TROUTE_COLLISION',
  'EK_TROUTE_UNMAPPED',
  'EK_TROUTE_DISABLED',
  'EK_TROUTE_CONTRACT',
  'EK_TROUTE_UPSTREAM',
  'EK_TROUTE_FORBIDDEN',
  'EK_TROUTE_TIMEOUT',
  'EK_TROUTE_CAPACITY',
  'EK_TCAP_UNAVAILABLE',
  'EK_TCAP_LIMIT_EXCEEDED',
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
