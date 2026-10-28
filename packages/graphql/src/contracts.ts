// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  Identity,
  MfaAssurance,
  OperationOptions,
  VerifiedTenantContext,
} from '@arkenivajs/core';

/** GraphQL operation kinds accepted by the optional server integration. */
export type GraphqlOperationKind = 'query' | 'mutation' | 'subscription';

/** Resolver context contains only request metadata and independently verified authentication. */
export interface GraphqlRequestContext {
  readonly requestId: string;
  readonly signal: AbortSignal;
  readonly operationName?: string;
  readonly identity?: Identity;
  readonly auth?: VerifiedTenantContext;
}

/** Field coordinates retain response aliases and list indexes in the response path. */
export interface GraphqlFieldInfo {
  readonly parentType: string;
  readonly fieldName: string;
  readonly operation: GraphqlOperationKind;
  readonly operationName?: string;
  readonly path: readonly (string | number)[];
}

/** Application services own row-level policy and business effects. */
export type GraphqlFieldResolver = (
  parent: unknown,
  args: Readonly<Record<string, unknown>>,
  context: GraphqlRequestContext,
  info: GraphqlFieldInfo,
) => unknown | Promise<unknown>;

/** Subscription sources must release their underlying handles when iteration ends. */
export type GraphqlSubscriptionSource = (
  parent: unknown,
  args: Readonly<Record<string, unknown>>,
  context: GraphqlRequestContext,
  info: GraphqlFieldInfo,
) => AsyncIterable<unknown> | Promise<AsyncIterable<unknown>>;

/** A subscription can separately map each authorized source event. */
export interface GraphqlSubscriptionResolver {
  readonly subscribe: GraphqlSubscriptionSource;
  readonly resolve?: GraphqlFieldResolver;
}

/** Schema type and field names select explicit application resolvers. */
export type GraphqlResolvers = Readonly<
  Record<string, Readonly<Record<string, GraphqlFieldResolver | GraphqlSubscriptionResolver>>>
>;

/** Ordered field inputs for a single request's batch. */
export interface GraphqlBatchLoadRequest {
  readonly parent: unknown;
  readonly args: Readonly<Record<string, unknown>>;
  readonly info: GraphqlFieldInfo;
}

/** Results preserve input order and length; missing authorized records use null. */
export type GraphqlBatchLoader = (
  requests: readonly GraphqlBatchLoadRequest[],
  context: GraphqlRequestContext,
) => Promise<readonly unknown[]>;

/** Loader caches belong to one request and cannot cross identity or tenant boundaries. */
export interface GraphqlLoaderDefinition {
  readonly load: GraphqlBatchLoader;
  readonly cache?: boolean;
  readonly maxBatchSize?: number;
}

/** Batch definitions use schema coordinates without exposing database adapters. */
export type GraphqlLoaders = Readonly<
  Record<string, Readonly<Record<string, GraphqlLoaderDefinition>>>
>;

/** Anonymous access requires an explicit Query root allowlist and its justification. */
export type GraphqlAuthenticationPolicy =
  | Readonly<{ required: true; scopes?: readonly string[]; assurance?: MfaAssurance }>
  | Readonly<{ required: false; publicRootFields: readonly string[]; reason: string }>;

/** Authorization precedes explicit resolvers and default property reads. */
export interface GraphqlAuthorizationInput {
  readonly context: GraphqlRequestContext;
  readonly field: GraphqlFieldInfo;
  readonly args: Readonly<Record<string, unknown>>;
  readonly parent: unknown;
}

/** Only an explicit true decision grants field access. */
export type GraphqlFieldAuthorization = (
  input: GraphqlAuthorizationInput,
) => boolean | Promise<boolean>;

/** Finite execution work limits are separate from monetary accounting. */
export interface GraphqlExecutionLimits {
  readonly maxDocumentBytes: number;
  readonly maxVariablesBytes: number;
  readonly maxResultBytes: number;
  readonly maxDepth: number;
  readonly maxComplexity: number;
  readonly maxAliases: number;
  readonly maxFieldExecutions: number;
  readonly maxCollectionItems: number;
  readonly maxOperationMs: number;
}

/** Production defaults disable introspection, IDE, GET and HTTP batching. */
export interface GraphqlSecuritySettings {
  readonly auth?: GraphqlAuthenticationPolicy;
  readonly authorizeField: GraphqlFieldAuthorization;
  readonly limits?: Partial<GraphqlExecutionLimits>;
  readonly introspection?: 'disabled' | 'authenticated';
  readonly introspectionScope?: string;
  readonly developerIDE?: boolean;
  readonly allowGetQueries?: boolean;
  readonly allowBatchedHttpRequests?: false;
}

/** The application-owned delivery port must verify tenant provenance and isolate namespaces. */
export interface GraphqlSubscriptionPubSub {
  subscribe(
    topic: string,
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): AsyncIterable<unknown>;
  publish(
    topic: string,
    payload: unknown,
    tenant: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<void>;
  close(options?: OperationOptions): Promise<void>;
}

/** Subscriptions require explicit transport bounds, origin policy and identity revalidation. */
export interface GraphqlSubscriptionSettings {
  readonly enabled: true;
  readonly pubsub: GraphqlSubscriptionPubSub;
  readonly maxConnections: number;
  readonly maxOperationsPerConnection: number;
  readonly maxQueuedEventsPerConnection: number;
  readonly revalidateIntervalMs: number;
  readonly allowedOrigins: readonly string[];
}

/** Complete startup declarations; registration remains separate from administrative service lookup. */
export interface GraphqlPluginSettings {
  readonly path?: string;
  readonly schema: string;
  readonly resolvers: GraphqlResolvers;
  readonly loaders?: GraphqlLoaders;
  readonly security: GraphqlSecuritySettings;
  readonly subscriptions?: GraphqlSubscriptionSettings;
}

/** Lifetime counters describe this process rather than the entire deployment. */
export interface GraphqlStats {
  readonly operations: number;
  readonly rejected: number;
  readonly activeOperations: number;
  readonly activeSubscriptions: number;
  readonly loaderBatches: number;
}

/** Trusted in-process diagnostics never create public schema or execution endpoints. */
export interface GraphqlService {
  stats(): GraphqlStats;
  health(): Readonly<{ ready: boolean; schemaLoaded: boolean; subscriptionsReady: boolean }>;
  schemaSdl(): string;
}
