import type { OperationOptions, Environment } from './contracts.js';

/** Type-only component ports; runtime implementations belong to independent adapters. */

/** Compile-time tenant brand; runtime verification must come from the authentication provider. */
export type TenantId = string & { readonly __brand: 'VerifiedTenantId' };

/** Minimum issuer-bound authentication assurance; this does not assert a regulatory AAL. */
export type MfaAssurance = 'single-factor' | 'mfa' | 'phishing-resistant';

/** Immutable issuer/audience-verified identity; claims may contain sensitive application data. */
export interface Identity {
  readonly subject: string;
  readonly issuer: string;
  readonly audience: readonly string[];
  readonly scopes: readonly string[];
  readonly claims: Readonly<Record<string, unknown>>;
  readonly assurance?: MfaAssurance;
}

/** Authorized single-tenant context. Serialization and object cloning do not preserve provenance. */
export interface VerifiedTenantContext {
  readonly tenantId: TenantId;
  readonly identity: Identity;
  readonly verifiedAt: string;
  readonly source: 'oidc' | 'service-identity';
}

/** Resource-server authentication and exact scope/tenant authorization. */
export interface AuthService {
  /**
   * Verify one bearer assertion against configured issuer, audience, signature and time policy.
   * @param authorizationHeader Single Authorization header; absence requires authentication.
   * @param options Cooperative cancellation and caller deadline, in milliseconds.
   * @returns A provider-owned immutable identity; no diagnostic header grants trust.
   * @throws KitError with EK_AUTH_REQUIRED, EK_AUTH_INVALID, EK_TIMEOUT or EK_ABORTED.
   */
  verifyBearer(
    authorizationHeader: string | undefined,
    options?: OperationOptions,
  ): Promise<Identity>;
  /** Require exact scope membership on a current verified identity; otherwise EK_AUTH_FORBIDDEN. */
  requireScope(identity: Identity, scope: string): void;
  /** Require a current issuer-bound policy decision; insufficient proof uses EK_MFA_ASSURANCE_REQUIRED. */
  requireAssurance(identity: Identity, requirement: MfaAssurance): void;
  /** Derive one authorized tenant from verified claims; ambiguous/foreign values use EK_TENANT_UNVERIFIED. */
  tenantFrom(identity: Identity): VerifiedTenantContext;
}

/** RouteContext shape used by the application facade. */
export interface RouteContext<
  P = Record<string, string>,
  Q = Record<string, unknown>,
  B = unknown,
> {
  readonly requestId: string;
  readonly params: P;
  readonly query: Q;
  readonly body: B;
  readonly signal: AbortSignal;
  readonly auth?: VerifiedTenantContext;
  readonly headers: Readonly<Record<string, string | undefined>>;
}

/** RouteHandler shape used by the application facade. */
export type RouteHandler<P, Q, B, R> = (ctx: RouteContext<P, Q, B>) => Promise<R> | R;

/** RouteDefinition shape used by the application facade. */
export interface RouteDefinition<P, Q, B, R> {
  schema: { params?: object; query?: object; body?: object; response: object };
  auth: { required: boolean; scopes?: readonly string[]; assurance?: MfaAssurance };
  handler: RouteHandler<P, Q, B, R>;
}

/** ApiMiddleware shape used by the application facade. */
export type ApiMiddleware = (ctx: RouteContext, next: () => Promise<void>) => Promise<void>;

/** ApiServer shape used by the application facade. */
export interface ApiServer {
  get<P, Q, B, R>(path: string, spec: RouteDefinition<P, Q, B, R>): void;
  post<P, Q, B, R>(path: string, spec: RouteDefinition<P, Q, B, R>): void;
  put<P, Q, B, R>(path: string, spec: RouteDefinition<P, Q, B, R>): void;
  patch<P, Q, B, R>(path: string, spec: RouteDefinition<P, Q, B, R>): void;
  delete<P, Q, B, R>(path: string, spec: RouteDefinition<P, Q, B, R>): void;
  registerMiddleware(stage: 'postAuthentication' | 'preHandler', fn: ApiMiddleware): void;
  openApiDocument(): Readonly<Record<string, unknown>>;
  native(): unknown;
}

/** OutboundHttpClient shape used by the application facade. */
export interface OutboundHttpClient {
  request(
    url: string,
    init: RequestInit & OperationOptions & { idempotencyKey?: string },
  ): Promise<Response>;
  get(url: string, options?: OperationOptions): Promise<Response>;
  post(
    url: string,
    body: unknown,
    options?: OperationOptions & { idempotencyKey?: string },
  ): Promise<Response>;
}

/** MeasureOptions shape used by the application facade. */
export interface MeasureOptions {
  attributes?: Readonly<Record<string, string | number | boolean>>;
}

/** Telemetry shape used by the application facade. */
export interface Telemetry {
  measure<T>(name: string, fn: () => Promise<T> | T, options?: MeasureOptions): Promise<T>;
  withSpan<T>(name: string, fn: () => Promise<T> | T, options?: MeasureOptions): Promise<T>;
  addCounter(
    name: string,
    value: number,
    attrs?: Readonly<Record<string, string | number | boolean>>,
  ): void;
  recordHistogram(
    name: string,
    value: number,
    attrs?: Readonly<Record<string, string | number | boolean>>,
  ): void;
  setGauge(
    name: string,
    value: number,
    attrs?: Readonly<Record<string, string | number | boolean>>,
  ): void;
  flush(options?: OperationOptions): Promise<void>;
}

/** MeterResultStatus shape used by the application facade. */
export type MeterResultStatus = 'ok' | 'error' | 'aborted' | 'unknown';

/** UsageQuantity shape used by the application facade. */
export interface UsageQuantity {
  readonly unit: 'bytes' | 'operations' | 'milliseconds' | 'items';
  readonly value: number;
  readonly source: 'observed' | 'derived';
}

/** MeteringEvent shape used by the application facade. */
export interface MeteringEvent {
  readonly schemaVersion: '1.0.0';
  readonly eventId: string;
  readonly tenantId: string;
  readonly traceId?: string;
  readonly requestId?: string;
  readonly operationId: string;
  readonly parentOperationId?: string;
  readonly service: string;
  readonly serviceVersion: string;
  readonly environment: Environment;
  readonly instanceId: string;
  readonly k8s?: { namespace?: string; pod?: string; container?: string; node?: string };
  readonly operation: string;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly durationMs: number;
  readonly status: MeterResultStatus;
  readonly counters: Readonly<Record<string, UsageQuantity>>;
  readonly quality: {
    readonly complete: boolean;
    readonly droppedChildCount: number;
    readonly missing: readonly string[];
  };
}

/** MeterEndReceipt shape used by the application facade. */
export interface MeterEndReceipt {
  readonly eventId: string;
  readonly accepted: boolean;
  readonly reason?: 'capacity' | 'disabled' | 'invalid';
}

/** MeterSession shape used by the application facade. */
export interface MeterSession {
  readonly operationId: string;
  recordUsage(name: string, usage: UsageQuantity): void;
  recordOperation(name: string, count?: number): void;
  recordError(error: unknown): void;
  end(status?: MeterResultStatus): MeterEndReceipt;
}

/** UsageMeter shape used by the application facade. */
export interface UsageMeter {
  start(input: {
    tenant: VerifiedTenantContext;
    operation: string;
    requestId?: string;
  }): MeterSession;
  measure<T>(
    input: { tenant: VerifiedTenantContext; operation: string; requestId?: string },
    fn: () => Promise<T> | T,
  ): Promise<T>;
  current(): MeterSession | undefined;
  flush(options?: OperationOptions): Promise<void>;
  stats(): Readonly<{
    enqueued: number;
    exported: number;
    dropped: number;
    failedExports: number;
    queueDepth: number;
  }>;
  snapshot(): Readonly<{ activeSessions: number; queueDepth: number; dropped: number }>;
}

/** Portable input values; native arrays, JSON objects, OUT binds and LOBs are adapter-specific. */
export type SqlValue = string | number | bigint | boolean | null | Date | Uint8Array;

/** Exact own named parameters; names use ASCII letters, digits and underscore, starting without a digit. */
export type SqlBindings = Readonly<Record<string, SqlValue>>;

/** SQL with :name placeholders; values remain separate from SQL text and identifiers. */
export interface SqlStatement {
  text: string;
  bindings?: SqlBindings;
}

/** Bounded materialization and cooperative cancellation; limits do not bound server work. */
export interface SqlQueryOptions extends OperationOptions {
  /** Default 10,000; range 1..100,000. Exceeding the limit rejects without partial success. */
  maxRows?: number;
}

/** Backend rows and honest result metadata; an unknown count remains null. */
export interface SqlResult<T extends object = Record<string, unknown>> {
  rows: readonly T[];
  rowCount: number | null;
  metadata: Readonly<{
    affectedRows?: number;
    insertId?: string | number | bigint;
    outputBinds?: Readonly<Record<string, unknown>>;
  }>;
}

/** One pinned connection, owned by its active transaction callback and never implicitly retried. */
export interface SqlTransaction {
  query<T extends object = Record<string, unknown>>(
    statement: SqlStatement,
    options?: SqlQueryOptions,
  ): Promise<SqlResult<T>>;
  execute(statement: SqlStatement, options?: OperationOptions): Promise<SqlResult>;
}

/** Named SQL connections; native clients and pools belong to independent adapters. */
export interface SqlProvider {
  /** Return bounded rows; oversized results use EK_DATABASE_QUERY with limitExceeded=true. */
  query<T extends object = Record<string, unknown>>(
    connectionName: string,
    statement: SqlStatement,
    options?: SqlQueryOptions,
  ): Promise<SqlResult<T>>;
  /** Fetch at most two rows: none returns null, one returns the row, two reject with EK_DATABASE_QUERY. */
  queryOne<T extends object = Record<string, unknown>>(
    connectionName: string,
    statement: SqlStatement,
    options?: OperationOptions,
  ): Promise<T | null>;
  /** Execute once and retain backend-provided rows and affected-row metadata without guessing counts. */
  execute(
    connectionName: string,
    statement: SqlStatement,
    options?: OperationOptions,
  ): Promise<SqlResult>;
  /**
   * Begin and commit on one connection, or roll back on callback failure; nesting rejects.
   * A lost/timed-out commit reports outcome='unknown'; primary and cleanup failures are retained.
   */
  transaction<T>(
    connectionName: string,
    handler: (tx: SqlTransaction) => Promise<T>,
    options?: OperationOptions,
  ): Promise<T>;
  /** Return false for normal unhealthy state; structural configuration failures still throw. */
  ping(connectionName: string, options?: OperationOptions): Promise<boolean>;
  /** Report only driver-observed counters; unsupported counters remain null. */
  stats(connectionName: string): Readonly<Record<string, number | null>>;
  /** Driver/pool escape hatch; advanced operations have adapter-specific instrumentation limits. */
  native(connectionName: string): unknown;
}

/** RedisProvider shape used by the application facade. */
export interface RedisProvider {
  get(key: string, options?: OperationOptions): Promise<string | null>;
  set(
    key: string,
    value: string,
    options?: OperationOptions & { ttlMs?: number; onlyIfAbsent?: boolean },
  ): Promise<boolean>;
  del(keys: readonly string[], options?: OperationOptions): Promise<number>;
  increment(key: string, amount?: number, options?: OperationOptions): Promise<number>;
  publish(channel: string, message: string, options?: OperationOptions): Promise<number>;
  native(): unknown;
}

/** EtcdValue shape used by the application facade. */
export interface EtcdValue {
  readonly key: string;
  readonly value: Uint8Array;
  readonly revision: bigint;
  readonly version: bigint;
}

/** EtcdWatchEvent shape used by the application facade. */
export interface EtcdWatchEvent {
  readonly type: 'put' | 'delete';
  readonly key: string;
  readonly value?: Uint8Array;
  readonly revision: bigint;
}

/** EtcdWatchHandle shape used by the application facade. */
export interface EtcdWatchHandle extends AsyncIterable<EtcdWatchEvent> {
  close(): Promise<void>;
}

/** EtcdLease shape used by the application facade. */
export interface EtcdLease {
  readonly id: string;
  keepAlive(): void;
  revoke(options?: OperationOptions): Promise<void>;
}

/** EtcdProvider shape used by the application facade. */
export interface EtcdProvider {
  get(key: string, options?: OperationOptions): Promise<EtcdValue | null>;
  put(
    key: string,
    value: Uint8Array,
    options?: OperationOptions & { leaseId?: string },
  ): Promise<void>;
  delete(key: string, options?: OperationOptions): Promise<boolean>;
  watch(prefix: string, options?: OperationOptions): Promise<EtcdWatchHandle>;
  grantLease(ttlSeconds: number, options?: OperationOptions): Promise<EtcdLease>;
  compareAndSwap(
    input: { key: string; expectedRevision: bigint; value: Uint8Array },
    options?: OperationOptions,
  ): Promise<boolean>;
  native(): unknown;
}

/** DocumentProvider shape used by the application facade. */
export interface DocumentProvider {
  findOne<T extends object>(
    collection: string,
    filter: Readonly<Record<string, unknown>>,
    options?: OperationOptions,
  ): Promise<T | null>;
  findMany<T extends object>(
    collection: string,
    filter: Readonly<Record<string, unknown>>,
    options?: OperationOptions & { limit?: number },
  ): Promise<readonly T[]>;
  insertOne<T extends object>(
    collection: string,
    document: T,
    options?: OperationOptions,
  ): Promise<string>;
  updateOne(
    collection: string,
    filter: Readonly<Record<string, unknown>>,
    update: Readonly<Record<string, unknown>>,
    options?: OperationOptions,
  ): Promise<number>;
  deleteOne(
    collection: string,
    filter: Readonly<Record<string, unknown>>,
    options?: OperationOptions,
  ): Promise<number>;
  aggregate<T extends object>(
    collection: string,
    pipeline: readonly Record<string, unknown>[],
    options?: OperationOptions,
  ): Promise<readonly T[]>;
  withTransaction<T>(
    handler: (session: unknown) => Promise<T>,
    options?: OperationOptions,
  ): Promise<T>;
  native(): unknown;
}

/** HealthRegistry shape used by the application facade. */
export interface HealthRegistry {
  live(): { status: 'live' };
  ready(): Promise<{ status: 'ready' | 'not_ready'; failing: readonly string[] }>;
}

/** TenantResolver shape used by the application facade. */
export type TenantResolver = (identity: Identity) => VerifiedTenantContext;

/** CacheProvider shape used by the application facade. */
export interface CacheProvider {
  get<T>(key: string, options?: OperationOptions): Promise<T | null>;
  set<T>(key: string, value: T, options?: OperationOptions & { ttlMs?: number }): Promise<void>;
  delete(key: string, options?: OperationOptions): Promise<boolean>;
}

/** MessageEnvelope shape used by the application facade. */
export interface MessageEnvelope<T> {
  readonly messageId: string;
  readonly topic: string;
  readonly payload: T;
  readonly correlationId?: string;
  readonly tenant?: VerifiedTenantContext;
}

/** Subscription shape used by the application facade. */
export interface Subscription {
  close(): Promise<void>;
}

/** MessageBus shape used by the application facade. */
export interface MessageBus {
  publish<T>(
    topic: string,
    payload: T,
    options?: OperationOptions & { correlationId?: string },
  ): Promise<{ messageId: string; acknowledged: boolean }>;
  subscribe<T>(
    topic: string,
    handler: (message: MessageEnvelope<T>) => Promise<void>,
    options?: OperationOptions,
  ): Promise<Subscription>;
}
