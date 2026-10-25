// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  ApiServer,
  OutboundHttpClient,
  AuthService,
  CacheProvider,
  MessageBus,
  SqlProvider,
  RedisProvider,
  EtcdProvider,
  DocumentProvider,
  Telemetry,
  UsageMeter,
  HealthRegistry,
  Identity,
  MfaAssurance,
} from './ports.js';

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
  | 'EK_MFA_POLICY'
  | 'EK_MFA_ASSURANCE_REQUIRED'
  | 'EK_MFA_INVALID'
  | 'EK_MFA_EXPIRED'
  | 'EK_MFA_REPLAY'
  | 'EK_MFA_RATE_LIMIT'
  | 'EK_MFA_STORAGE'
  | 'EK_MFA_ALREADY_ENROLLED'
  | 'EK_MFA_ENROLLMENT_EXPIRED'
  | 'EK_MFA_CHALLENGE_EXPIRED'
  | 'EK_MFA_CREDENTIAL_CONFLICT'
  | 'EK_MFA_COUNTER_REGRESSION'
  | 'EK_TELEMETRY_CONFLICT'
  | 'EK_METER_SESSION'
  | 'EK_METER_CAPACITY'
  | 'EK_METER_EXPORT'
  | 'EK_HEALTH_NOT_READY'
  | 'EK_INTERNAL';
/** Internal developer error details; only the safe envelope crosses external boundaries. */
export interface KitErrorOptions {
  code: ErrorCode;
  message: string;
  cause?: unknown;
  retryable?: boolean;
  details?: Readonly<Record<string, string | number | boolean | null>>;
}

/** Cancellation and integer millisecond deadlines for asynchronous operations. */
export interface OperationOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

/** Typed top-level access and immutable atomic configuration generations. */
export interface ConfigService<T extends Record<string, unknown> = Record<string, unknown>> {
  get<K extends keyof T>(key: K): T[K] | undefined;
  require<K extends keyof T>(key: K): NonNullable<T[K]>;
  has<K extends keyof T>(key: K): boolean;
  snapshot(): Readonly<T>;
  reload(updates: Partial<T>): Promise<Readonly<T>>;
}

/** LifecycleState contract for explicit application composition. */
export type LifecycleState =
  'CREATED' | 'INITIALIZING' | 'READY' | 'DRAINING' | 'FAILED' | 'CLOSED';

/** Environment contract for explicit application composition. */
export type Environment = 'development' | 'test' | 'production';

/** LogLevel contract for explicit application composition. */
export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal' | 'silent';

/** Logger contract for explicit application composition. */
export interface Logger {
  trace(message: string, fields?: Readonly<Record<string, unknown>>): void;
  debug(message: string, fields?: Readonly<Record<string, unknown>>): void;
  info(message: string, fields?: Readonly<Record<string, unknown>>): void;
  warn(message: string, fields?: Readonly<Record<string, unknown>>): void;
  error(message: string, fields?: Readonly<Record<string, unknown>>): void;
  fatal(message: string, fields?: Readonly<Record<string, unknown>>): void;
  child(fields: Readonly<Record<string, unknown>>): Logger;
  setLevel(level: LogLevel): void;
  flush(options?: OperationOptions): Promise<void>;
}

/** ProcessSnapshot contract for explicit application composition. */
export interface ProcessSnapshot {
  readonly timestamp: string;
  readonly processId: number;
  readonly cpuUserMicros: number;
  readonly cpuSystemMicros: number;
  readonly memoryRssBytes: number;
  readonly heapUsedBytes: number;
  readonly eventLoopUtilization?: number;
  readonly eventLoopDelayP99Ms?: number;
}

/** Diagnostics contract for explicit application composition. */
export interface Diagnostics {
  snapshot(): ProcessSnapshot;
}

/** PluginContext contract for explicit application composition. */
export interface PluginContext {
  readonly logger: Logger;
  readonly options: ApplicationOptions;
  provide<T>(key: symbol, instance: T): void;
  require<T>(key: symbol): T;
}

/** Plugin contract for explicit application composition. */
export interface Plugin {
  readonly id: string;
  readonly version: string;
  readonly dependencies?: readonly string[];
  readonly capabilities: ReadonlySet<string>;
  init(context: PluginContext): Promise<void> | void;
  close(context: PluginContext): Promise<void> | void;
}

/** DatabaseDriver contract for explicit application composition. */
export type DatabaseDriver =
  'postgresql' | 'mysql' | 'mariadb' | 'oracle' | 'redis' | 'etcd' | 'mongodb';

/** DatabaseDefinition contract for explicit application composition. */
export interface DatabaseDefinition {
  readonly driver: DatabaseDriver;
  readonly connectionStringEnv?: string;
  readonly endpoints?: readonly string[];
  readonly poolMin?: number;
  readonly poolMax?: number;
}

/** ApplicationOptions contract for explicit application composition. */
export interface ApplicationOptions {
  readonly service: { name: string; version: string; environment: Environment };
  readonly http?: { host: string; port: number; requestTimeoutMs?: number };
  readonly plugins?: readonly Plugin[];
  readonly databases?: Readonly<Record<string, DatabaseDefinition>>;
  readonly security?: {
    issuer: string;
    audience: string;
    tenantClaim?: string;
    algorithms?: readonly string[];
    assuranceResolver?: (identity: Identity) => MfaAssurance;
  };
  readonly logging?: { level: LogLevel };
  readonly telemetry?: {
    mode: 'off' | 'minimal' | 'standard' | 'detailed';
    samplingRatio?: number;
  };
  readonly metering?: {
    enabled: boolean;
    queueCapacity?: number;
    exporter?: 'jsonl' | 'http' | 'otlp';
    path?: string;
    endpoint?: string;
  };
}

/** Application contract for explicit application composition. */
export interface Application {
  readonly state: LifecycleState;
  readonly logger: Logger;
  readonly api: ApiServer;
  readonly config: ConfigService;
  readonly http: OutboundHttpClient;
  readonly auth?: AuthService;
  readonly cache?: CacheProvider;
  readonly messaging?: MessageBus;
  readonly sql: SqlProvider;
  readonly redis?: RedisProvider;
  readonly etcd?: EtcdProvider;
  readonly mongo?: DocumentProvider;
  readonly telemetry: Telemetry;
  readonly meter: UsageMeter;
  readonly diagnostics: Diagnostics;
  readonly health: HealthRegistry;
  start(): Promise<void>;
  stop(options?: { timeoutMs?: number }): Promise<void>;
}
