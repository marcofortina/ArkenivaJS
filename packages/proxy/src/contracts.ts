// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
import type { TlsProfile } from '@arkenivajs/security-mtls';

export type SecretRefResolver = (reference: string, options?: OperationOptions) => Promise<string>;
export type ProxyAuth =
  | Readonly<{ required: true; scopes?: readonly string[] }>
  | Readonly<{ required: false; reason: string }>;
export type ProxyDestinationPolicy =
  | Readonly<{ kind: 'public-only' }>
  | Readonly<{
      kind: 'private-allowlisted';
      allowedHosts: readonly string[];
      allowedCidrs: readonly string[];
    }>;
export interface ProxyRouteConfig {
  readonly routeId: string;
  readonly prefix: string;
  readonly upstreamOrigin: string;
  readonly rewritePrefix?: string;
  readonly methods: readonly ('GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE')[];
  readonly auth: ProxyAuth;
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
  readonly timeoutMs: number;
  readonly destinationPolicy: ProxyDestinationPolicy;
  readonly upstreamCaFile?: string;
  /** Optional approved mTLS profile; requires the existing mTLS capability and asynchronous peer policy. */
  readonly upstreamTlsProfile?: TlsProfile;
  readonly identityDelegation?: 'none' | 'validated-service-credential';
  readonly serviceCredentialSecretRef?: string;
}
export interface ProxyPluginSettings {
  readonly routes: readonly ProxyRouteConfig[];
  readonly resolveSecret?: SecretRefResolver;
}
export interface ProxyService {
  stats(): Readonly<{
    activeRequests: number;
    forwardedRequests: number;
    rejectedRequests: number;
    observedRequestBytes: number;
    observedResponseBytes: number;
  }>;
  health(): Readonly<{ configuredRoutes: number; ready: boolean }>;
}
