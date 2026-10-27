// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
import type {
  TrustedSecurityAuthority,
  IdentitySubject,
  SecurityStoreSettings,
  KeyedDigestProvider,
} from '@arkenivajs/security-sessions';
export type {
  SecurityStoreSettings,
  KeyedDigestProvider,
  TrustedSecurityAuthority,
  IdentitySubject,
  SecurityTransactionalStore,
} from '@arkenivajs/security-sessions';

export interface HttpSecurityPolicy {
  readonly contentSecurityPolicy: Readonly<Record<string, readonly string[]>>;
  readonly hstsMaxAgeSeconds: number;
  readonly csrfEnabled: boolean;
  readonly frameAncestors: readonly string[];
}
/** Actual native request observations; cookies are credentials, never identity proof or telemetry. */
export interface HttpSecurityRequest {
  readonly method: string;
  readonly route: string;
  readonly cookies: Readonly<Record<string, string>>;
  readonly secure: boolean;
}
export type HttpSecurityAuthorizationContext = Parameters<TrustedSecurityAuthority['require']>[2] &
  Readonly<{ request?: HttpSecurityRequest }>;
export interface HttpSecurityAuthority extends TrustedSecurityAuthority {
  require(
    action: string,
    subject: IdentitySubject | undefined,
    context: HttpSecurityAuthorizationContext,
    options?: OperationOptions,
  ): Promise<IdentitySubject>;
}
/** Resolve a real session through the application's authentication service; IDs alone confer no authority. */
export interface CookieSessionProvider {
  resolve(
    request: HttpSecurityRequest,
    options?: OperationOptions,
  ): Promise<Readonly<{ sessionId: string }>>;
}
export interface CookieSecurityRoute {
  readonly method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  readonly path: string;
}
export interface SecurityHttpPluginSettings {
  readonly policy: HttpSecurityPolicy;
  readonly csrfStore: SecurityStoreSettings;
  readonly csrfHmac: KeyedDigestProvider;
  readonly csrfKeyRef: string;
  readonly authority: HttpSecurityAuthority;
  readonly allowedOrigins?: readonly string[];
  readonly cookieRoutes?: readonly CookieSecurityRoute[];
  readonly cookieSession?: CookieSessionProvider;
  readonly trustedProxyCidrs?: readonly string[];
}
export interface SecurityHttpService {
  installHeaders(policy: HttpSecurityPolicy): void;
  csrfToken(context: Readonly<{ sessionId: string }>, options?: OperationOptions): Promise<string>;
  verifyCsrf(
    context: Readonly<{ sessionId: string; origin: string }>,
    token: string,
    options?: OperationOptions,
  ): Promise<void>;
  getEffectivePolicy(): HttpSecurityPolicy;
}
