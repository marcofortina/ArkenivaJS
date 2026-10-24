/** Stable framework error codes for typed public failures. */
export type ErrorCode =
  | 'EK_CONFIG_INVALID'
  | 'EK_CONFIG_MISSING'
  | 'EK_CONFIG_RELOAD_REJECTED'
  | 'EK_LIFECYCLE_STATE'
  | 'EK_PLUGIN_DUPLICATE'
  | 'EK_PLUGIN_DEPENDENCY'
  | 'EK_PLUGIN_FAILED'
  | 'EK_ABORTED'
  | 'EK_TIMEOUT'
  | 'EK_UNSUPPORTED_CAPABILITY'
  | 'EK_RESOURCE_CLOSED'
  | 'EK_DATABASE_CONNECT'
  | 'EK_DATABASE_QUERY'
  | 'EK_DATABASE_CONSTRAINT'
  | 'EK_DATABASE_CONFLICT'
  | 'EK_DATABASE_POOL_TIMEOUT'
  | 'EK_DATABASE_TRANSACTION'
  | 'EK_DATABASE_UNAVAILABLE'
  | 'EK_KV_CONFLICT'
  | 'EK_DOCUMENT_OPERATION'
  | 'EK_BACKEND_UNAVAILABLE'
  | 'EK_HTTP_VALIDATION'
  | 'EK_HTTP_NOT_FOUND'
  | 'EK_HTTP_UPSTREAM'
  | 'EK_HTTP_RATE_LIMIT'
  | 'EK_AUTH_REQUIRED'
  | 'EK_AUTH_INVALID'
  | 'EK_AUTH_FORBIDDEN'
  | 'EK_TENANT_UNVERIFIED'
  | 'EK_TELEMETRY_CONFLICT'
  | 'EK_METER_SESSION'
  | 'EK_METER_CAPACITY'
  | 'EK_METER_EXPORT'
  | 'EK_HEALTH_NOT_READY'
  | 'EK_INTERNAL';
export interface KitErrorOptions {
  code: ErrorCode;
  message: string;
  cause?: unknown;
  retryable?: boolean;
  details?: Readonly<Record<string, string | number | boolean | null>>;
}
