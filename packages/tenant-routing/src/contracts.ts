// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  MfaAssurance,
  OperationOptions,
  RouteContext,
  VerifiedTenantContext,
  SqlProvider,
  Environment,
} from '@arkenivajs/core';

/** Deployment-owned logical identity, independent of handler names and upstream URLs. */
export type TenantOperationId = string;
export type TenantHttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export interface TenantOperationSchemas {
  readonly params?: Readonly<Record<string, unknown>>;
  readonly query?: Readonly<Record<string, unknown>>;
  readonly body?: Readonly<Record<string, unknown>>;
  readonly response: Readonly<Record<string, unknown>>;
}
export interface TenantOperationPolicy {
  readonly requiredScopes: readonly string[];
  readonly assurance?: MfaAssurance;
}
/** All resource bounds are explicit; concurrency applies to one operation in one instance. */
export interface TenantOperationDefinition {
  readonly id: TenantOperationId;
  readonly method: TenantHttpMethod;
  readonly path: string;
  readonly schemas: TenantOperationSchemas;
  readonly policy: TenantOperationPolicy;
  readonly label: string;
  readonly maxConcurrency: number;
  readonly maxBodyBytes: number;
  readonly maxResponseBytes: number;
  readonly timeoutMs: number;
}
export interface TenantLocalImplementation {
  readonly id: string;
  readonly kind: 'handler';
  readonly handlerKey: string;
}
export interface TenantHttpImplementation {
  readonly id: string;
  readonly kind: 'http';
  readonly upstreamKey: string;
  readonly upstreamPath: string;
  readonly method: TenantHttpMethod;
  readonly requestTransformerKey?: string;
  readonly responseTransformerKey?: string;
  /** @deprecated Response-transform migration alias; cannot accompany responseTransformerKey. */
  readonly transformerKey?: string;
}
export type TenantImplementation = TenantLocalImplementation | TenantHttpImplementation;
export interface TenantOperationBinding {
  readonly tenantId: string;
  readonly operationId: TenantOperationId;
  readonly implementationId: string;
  readonly enabled: boolean;
  readonly discoverable?: boolean;
}
/** Content revision is immutable; activating even a rollback requires a greater generation. */
export interface TenantRegistrySnapshotV1_1 {
  readonly schemaVersion: '1.1.0';
  readonly revision: string;
  readonly activationGeneration: number;
  readonly contentChecksum: string;
  readonly activatedAt: string;
  readonly operations: readonly TenantOperationDefinition[];
  readonly implementations: readonly TenantImplementation[];
  readonly bindings: readonly TenantOperationBinding[];
}
/** Historical type name; active snapshots still require the complete 1.1.0 shape. */
export type TenantRegistrySnapshotV1 = TenantRegistrySnapshotV1_1;
export interface TenantRegistryActivationCheckpoint {
  accept(
    input: {
      scope: string;
      activationGeneration: number;
      revision: string;
      contentChecksum: string;
    },
    options?: OperationOptions,
  ): Promise<void>;
}
export interface TenantRegistryProvider {
  loadSnapshot(options?: OperationOptions): Promise<TenantRegistrySnapshotV1_1>;
}
export interface TenantRegistryFileOptions {
  readonly absolutePath: string;
  readonly maxBytes: number;
  readonly activationCheckpoint?: TenantRegistryActivationCheckpoint;
  /** Defaults to production, which requires root-owned deployment paths and private file modes. */
  readonly environment?: Environment;
  /** All deployment static roots; a registry may not reside inside any of them. */
  readonly publicRoots?: readonly string[];
}
/** Existing application SQL ownership is mandatory; providers never create hidden pools. */
export interface TenantRegistrySqlOptions {
  readonly connectionName: string;
  readonly sql: SqlProvider;
  readonly storageKey: string;
  /** Server-owned allowlist of logical keys to validated schema/table prefixes. */
  readonly storagePrefixes?: Readonly<Record<string, string>>;
  readonly activationCheckpoint?: TenantRegistryActivationCheckpoint;
}
export type TenantOperationHandler = (context: RouteContext) => Promise<unknown> | unknown;
export type TenantRequestTransformer = (
  payload: unknown,
  context: RouteContext,
) => unknown | Promise<unknown>;
export type TenantResponseTransformer = (
  payload: unknown,
  context: RouteContext,
) => unknown | Promise<unknown>;
export interface TenantUpstreamCredentials {
  readonly authorizationHeader: string;
  readonly expiresAt: string;
  readonly audience: string;
  readonly scopes: readonly string[];
}
export interface TenantUpstreamCredentialProvider {
  get(
    input: {
      upstreamKey: string;
      audience: string;
      scopes: readonly string[];
      tenant: VerifiedTenantContext;
      operationId: TenantOperationId;
    },
    options?: OperationOptions,
  ): Promise<TenantUpstreamCredentials>;
}
/** Trusted network catalog is independent of tenant registry mappings and browser input. */
export interface ApprovedUpstream {
  readonly key: string;
  readonly origin: string;
  readonly allowedHostnames: readonly string[];
  readonly allowedCidrs: readonly string[];
  readonly tlsCaFile?: string;
  readonly connectionTimeoutMs: number;
  readonly allowRedirects: false;
  readonly forwardClientAuthorization?: false;
  readonly serviceAuth?: Readonly<{ audience: string; scopes: readonly string[] }>;
}
export interface TenantRoutingAuthorizationInput {
  readonly tenant: VerifiedTenantContext;
  readonly operationId: TenantOperationId;
  readonly policy: TenantOperationPolicy;
}
export interface TenantRoutingPluginSettings {
  readonly registry: TenantRegistryProvider;
  readonly handlers: Readonly<Record<string, TenantOperationHandler>>;
  readonly requestTransformers?: Readonly<Record<string, TenantRequestTransformer>>;
  readonly responseTransformers?: Readonly<Record<string, TenantResponseTransformer>>;
  /** @deprecated Response catalog migration alias; cannot accompany responseTransformers. */
  readonly transformers?: Readonly<Record<string, TenantResponseTransformer>>;
  readonly credentialProvider?: TenantUpstreamCredentialProvider;
  /** Opt-in borrowed transport; the application owns its client and lifecycle. */
  readonly eventExporter?: TenantRoutingEventExporter;
  readonly approvedUpstreams?: readonly ApprovedUpstream[];
  readonly capabilitiesPath?: string;
  /** Per authorized response: default 1000, positive integer no greater than 5000. */
  readonly maxCapabilities?: number;
  readonly authorize: (input: TenantRoutingAuthorizationInput) => Promise<boolean> | boolean;
  readonly activation: 'startup';
}
export interface TenantResolution {
  readonly operationId: TenantOperationId;
  readonly implementationId: string;
  readonly revision: string;
  readonly activationGeneration: number;
  readonly kind: TenantImplementation['kind'];
}
/** Administrative resolution never grants permission to execute an operation. */
export interface TenantApiService {
  resolve(operationId: TenantOperationId, tenant: VerifiedTenantContext): TenantResolution | null;
  revision(): string;
  operations(): readonly TenantOperationId[];
}
export interface TenantPublicCapability {
  readonly operationId: TenantOperationId;
  readonly method: TenantHttpMethod;
  readonly path: string;
  readonly label: string;
}
export interface TenantCapabilitiesResponse {
  readonly schemaVersion: '1.0.0';
  readonly revision: string;
  readonly activationGeneration: number;
  readonly capabilities: readonly TenantPublicCapability[];
}
export interface TenantCapabilitiesService {
  list(
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<TenantCapabilitiesResponse>;
}
export interface TenantRoutingService {
  readonly api: TenantApiService;
  readonly capabilities: TenantCapabilitiesService;
  readonly events?: Readonly<{
    stats(): Readonly<{
      queued: number;
      inFlight: number;
      exported: number;
      dropped: number;
      failedExports: number;
    }>;
    flush(options?: OperationOptions): Promise<void>;
  }>;
  stats(): Readonly<{
    operations: number;
    bindings: number;
    requests: number;
    rejected: number;
    unavailable: number;
  }>;
}
/** Supplementary routing evidence; it does not modify technical metering event v1. */
export interface TenantRoutingEventV1 {
  readonly schemaVersion: '1.0.0';
  readonly eventId: string;
  readonly requestId: string;
  readonly traceId?: string;
  readonly tenantId: string;
  readonly operationId: TenantOperationId;
  readonly registryRevision: string;
  readonly registryActivationGeneration: number;
  readonly implementationId?: string;
  readonly implementationKind?: TenantImplementation['kind'];
  readonly durationMs: number;
  readonly status: 'ok' | 'error' | 'aborted' | 'unknown';
  readonly quality: Readonly<{ complete: boolean; missing: readonly string[] }>;
}

/** Acknowledges a complete immutable batch; errors never acknowledge delivery. */
export interface TenantRoutingEventExporter {
  export(events: readonly TenantRoutingEventV1[], options: OperationOptions): Promise<void>;
}
