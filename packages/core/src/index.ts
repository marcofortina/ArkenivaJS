// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export { KitError } from './errors.js';
export type { ErrorCode, KitErrorOptions } from './contracts.js';
export type { ConfigService, OperationOptions } from './contracts.js';
export type { Telemetry, MeasureOptions } from './ports.js';
export type {
  UsageMeter,
  MeterSession,
  MeteringEvent,
  MeterEndReceipt,
  MeterResultStatus,
  UsageQuantity,
} from './ports.js';
export type { OutboundHttpClient } from './ports.js';
export type { RedisProvider } from './ports.js';
export type { DocumentProvider } from './ports.js';
export type {
  CacheProvider,
  HealthRegistry,
  MessageBus,
  MessageEnvelope,
  Subscription,
} from './ports.js';
export type {
  EtcdProvider,
  EtcdValue,
  EtcdWatchEvent,
  EtcdWatchHandle,
  EtcdLease,
} from './ports.js';
export type {
  SqlValue,
  SqlBindings,
  SqlStatement,
  SqlQueryOptions,
  SqlResult,
  SqlTransaction,
  SqlProvider,
} from './ports.js';
export type {
  AuthService,
  Identity,
  TenantId,
  VerifiedTenantContext,
  MfaAssurance,
} from './ports.js';
export type {
  ApiServer,
  RouteContext,
  RouteDefinition,
  RouteHandler,
  ApiMiddleware,
} from './ports.js';
export type {
  Application,
  ApplicationOptions,
  LifecycleState,
  Environment,
  Plugin,
  PluginContext,
  Logger,
  LogLevel,
  Diagnostics,
  ProcessSnapshot,
  DatabaseDefinition,
  DatabaseDriver,
} from './contracts.js';
export { createApplication, COMPONENTS, APPLICATION_SIGNAL } from './application.js';
export {
  DEFAULT_SHUTDOWN_TIMEOUT_MS,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_SQL_TIMEOUT_MS,
  DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
  DEFAULT_METER_QUEUE_CAPACITY,
  METER_EVENT_SCHEMA_VERSION,
} from './defaults.js';
