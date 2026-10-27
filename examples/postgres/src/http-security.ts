// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
import type { SessionService, SessionIdentity } from '@arkenivajs/security-sessions';
import type {
  HttpSecurityRequest,
  IdentitySubject,
  SecurityHttpPluginSettings,
  SecurityStoreSettings,
  KeyedDigestProvider,
} from '@arkenivajs/security-http';

export interface CookieSecurityDependencies {
  readonly sessions: SessionService;
  readonly store: SecurityStoreSettings;
  readonly hmac: KeyedDigestProvider;
  readonly hmacKeyRef: string;
  readonly allowedOrigins: readonly string[];
  /** Resolve the verified session's current account, tenant and operation policy at runtime. */
  readonly authorize: (
    session: SessionIdentity,
    action: 'security-http.issue' | 'security-http.verify',
    options?: OperationOptions,
  ) => Promise<IdentitySubject>;
  /** Optional server-owned authenticated context for non-HTTP calls; never populated from a request body. */
  readonly authenticatedSessionToken?: () => string | undefined;
}

/** Compose the existing session service and durable store without trusting a caller's session ID. */
export function cookieSecuritySettings(
  dependencies: CookieSecurityDependencies,
): SecurityHttpPluginSettings {
  const credential = (request?: HttpSecurityRequest) =>
    request?.cookies['__Host-session'] ?? dependencies.authenticatedSessionToken?.();
  const validate = async (request: HttpSecurityRequest | undefined, options?: OperationOptions) => {
    const token = credential(request);
    if (!token) throw new Error('An authenticated session credential is required');
    return dependencies.sessions.validate(token, options);
  };
  return {
    policy: {
      contentSecurityPolicy: { 'default-src': ["'none'"], 'base-uri': ["'none'"] },
      frameAncestors: ["'none'"],
      csrfEnabled: true,
      hstsMaxAgeSeconds: 31536000,
    },
    csrfStore: dependencies.store,
    csrfHmac: dependencies.hmac,
    csrfKeyRef: dependencies.hmacKeyRef,
    allowedOrigins: dependencies.allowedOrigins,
    cookieRoutes: [{ method: 'POST', path: '/protected' }],
    cookieSession: {
      async resolve(request, options) {
        const session = await validate(request, options);
        await dependencies.authorize(session, 'security-http.verify', options);
        return { sessionId: session.sessionId };
      },
    },
    authority: {
      async require(action, _hint, context, options) {
        if (action !== 'security-http.issue' && action !== 'security-http.verify')
          throw new Error('The HTTP security action is not permitted');
        const session = await validate(context.request, options);
        if (session.sessionId !== context.sessionId)
          throw new Error('The session context does not match its authenticated credential');
        return dependencies.authorize(session, action, options);
      },
    },
  };
}
