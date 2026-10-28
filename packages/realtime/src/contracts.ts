// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions, VerifiedTenantContext } from '@arkenivajs/core';

export interface RealtimePolicy {
  readonly requireAuth: true;
  readonly maxConnectionsPerTenant: number;
  readonly maxMessageBytes: number;
  readonly maxBufferBytes: number;
  readonly heartbeatMs: number;
  readonly idleTimeoutMs: number;
}
export interface RealtimeMessage {
  readonly channel: string;
  readonly payload: Uint8Array;
  readonly id?: string;
}
export interface RealtimeSession {
  readonly authenticatedTenant: VerifiedTenantContext;
  readonly signal: AbortSignal;
  send(message: RealtimeMessage, options?: OperationOptions): Promise<void>;
  receive(): AsyncIterable<RealtimeMessage>;
}
export interface SseEvent {
  readonly id: string;
  readonly type: string;
  readonly data: string;
}
export interface SseSourceContext {
  readonly tenant: VerifiedTenantContext;
  readonly lastEventId?: string;
  readonly signal: AbortSignal;
}
export interface SseSource {
  readonly usage?: 'production' | 'test-only';
  readonly kind: 'durable' | 'pubsub';
  /** Required for durable resume: complete ownership/retention checks before HTTP headers are committed. */
  validateCursor?(context: SseSourceContext, options?: OperationOptions): Promise<void>;
  subscribe(context: SseSourceContext): AsyncIterable<SseEvent>;
}
export interface RealtimeService {
  websocket(
    path: string,
    policy: RealtimePolicy,
    handler: (session: RealtimeSession) => Promise<void>,
  ): void;
  sse(path: string, policy: RealtimePolicy, source: SseSource): void;
  publish(
    channel: string,
    message: Uint8Array,
    context: VerifiedTenantContext,
    options?: OperationOptions,
  ): Promise<void>;
  close(): Promise<void>;
}
export type RealtimeStartupRoute =
  | Readonly<{ kind: 'websocket'; path: string; handlerKey: string; policyKey: string }>
  | Readonly<{ kind: 'sse'; path: string; sourceKey: string; policyKey: string }>;
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** The configured authority independently authenticates the immutable request on admission and reauthorization. */
export interface RealtimeIdentityAuthority {
  readonly usage?: 'production' | 'test-only';
  authenticate(
    request: Readonly<{
      method: string;
      path: string;
      headers: Readonly<Record<string, string | undefined>>;
    }>,
    options?: OperationOptions,
  ): Promise<VerifiedTenantContext>;
}
export interface RealtimePluginSettings {
  readonly routes: readonly RealtimeStartupRoute[];
  readonly websocketHandlers: Readonly<Record<string, (session: RealtimeSession) => Promise<void>>>;
  readonly sseSources: Readonly<Record<string, SseSource>>;
  readonly policies: Readonly<Record<string, RealtimePolicy>>;
  readonly pubsub?: Readonly<{ provider: 'redis' | 'nats'; connectionName: string }>;
  readonly policy: BoundedRuntimePolicy;
  /** Cookie-bearing browser streams require an explicit exact HTTPS/HTTP origin allowlist. */
  readonly allowedOrigins?: readonly string[];
  /** Optional session integration still must return context minted by the application's actual auth service. */
  readonly identityAuthority?: RealtimeIdentityAuthority;
}
