// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions, VerifiedTenantContext, MfaAssurance } from '@arkenivajs/core';
import type { TlsProfile } from '@arkenivajs/security-mtls';

export interface GrpcPolicy {
  readonly maxInboundBytes: number;
  readonly maxOutboundBytes: number;
  readonly concurrencyLimit: number;
  readonly requireAuthentication: boolean;
  readonly methodAllowlist: readonly string[];
}
export interface GrpcCallOptions extends OperationOptions {
  readonly metadata?: Readonly<Record<string, string>>;
}
export type GrpcHandler = (
  request: unknown,
  context: Readonly<{
    authenticatedTenant?: VerifiedTenantContext;
    signal: AbortSignal;
  }>,
) => Promise<unknown>;
export interface GrpcClient {
  unary<T = unknown>(method: string, input: unknown, options?: GrpcCallOptions): Promise<T>;
  serverStream<T = unknown>(
    method: string,
    input: unknown,
    options?: GrpcCallOptions,
  ): AsyncIterable<T>;
  /** Trusted access to the actual approved client retains transport and lifecycle ownership. */
  native(): unknown;
}
export interface GrpcService {
  registerService(
    descriptor: string,
    handlers: Readonly<Record<string, GrpcHandler>>,
    policy: GrpcPolicy,
  ): void;
  client(serviceName: string): GrpcClient;
  nativeServer(): unknown;
  close(): Promise<void>;
}
export type IdentitySubject = Readonly<{
  issuer: string;
  subject: string;
  tenant?: VerifiedTenantContext;
}>;
export interface TrustedSecurityAuthority {
  require(
    action: string,
    subject: IdentitySubject | undefined,
    context: Readonly<{
      tenant?: VerifiedTenantContext;
      assurance?: MfaAssurance;
      sessionId?: string;
    }>,
    options?: OperationOptions,
  ): Promise<IdentitySubject>;
}
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
export interface GrpcServiceProfile {
  readonly name: string;
  readonly descriptorFile: string;
  readonly allowedMethods: readonly string[];
  readonly endpoint?: string;
  /** Explicit client-side TLS profile; omission is valid only with one configured profile. */
  readonly tlsProfile?: string;
  readonly listener?: Readonly<{ host: string; port: number; tlsProfile: string }>;
  readonly maxMessageBytes: number;
}
export interface GrpcPluginSettings {
  readonly services: readonly GrpcServiceProfile[];
  readonly handlers: Readonly<
    Record<
      string,
      Readonly<{
        descriptor: string;
        handlers: Readonly<Record<string, GrpcHandler>>;
        policy: GrpcPolicy;
      }>
    >
  >;
  readonly tlsProfiles: Readonly<Record<string, TlsProfile>>;
  readonly authority: TrustedSecurityAuthority;
  readonly policy: BoundedRuntimePolicy;
}
