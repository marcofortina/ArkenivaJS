// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { types } from 'node:util';
import type { FastifyRequest } from 'fastify';
import type {
  AuthService,
  Identity,
  OperationOptions,
  VerifiedTenantContext,
} from '@arkenivajs/core';
import type { Settings } from './settings.js';
import { failure } from './validation.js';

export function requestIdentity(request: FastifyRequest, settings: Settings) {
  const headers: Record<string, string | undefined> = Object.create(null);
  let bytes = 0;
  for (const [name, value] of Object.entries(request.headers)) {
    const captured = Array.isArray(value) ? value.join(',') : value;
    if (captured !== undefined) {
      bytes += Buffer.byteLength(name) + Buffer.byteLength(captured);
      if (bytes > 32768) throw failure('EK_REALTIME_AUTH');
    }
    headers[name] = captured;
  }
  const origin = headers.origin;
  if (
    (headers.cookie !== undefined || (origin !== undefined && settings.origins.length)) &&
    (origin === undefined || !settings.origins.includes(origin))
  )
    throw failure('EK_AUTH_FORBIDDEN');
  return Object.freeze({
    method: request.method,
    path: request.routeOptions.url ?? '',
    headers: Object.freeze(headers),
  });
}
export type RequestIdentity = ReturnType<typeof requestIdentity>;
/** Verify actual identity provenance through the auth service, independently of structural tenant brands. */
export function verifiedTenant(auth: AuthService, value: unknown): value is VerifiedTenantContext {
  if (!value || typeof value !== 'object' || types.isProxy(value)) return false;
  const identity = Object.getOwnPropertyDescriptor(value, 'identity');
  if (!identity || !('value' in identity)) return false;
  try {
    return auth.tenantFrom(identity.value as Identity) === value;
  } catch {
    return false;
  }
}
export async function authenticate(
  auth: AuthService,
  settings: Settings,
  request: RequestIdentity,
  options: OperationOptions,
): Promise<VerifiedTenantContext> {
  try {
    const context = settings.authority
      ? await settings.authority.authenticate(request, options)
      : auth.tenantFrom(await auth.verifyBearer(request.headers.authorization, options));
    if (!verifiedTenant(auth, context)) throw failure('EK_REALTIME_AUTH');
    return context;
  } catch {
    if (options.signal?.aborted) throw failure('EK_ABORTED');
    throw failure('EK_REALTIME_AUTH');
  }
}
export function sameIdentity(left: VerifiedTenantContext, right: VerifiedTenantContext): boolean {
  return (
    left.tenantId === right.tenantId &&
    left.identity.issuer === right.identity.issuer &&
    left.identity.subject === right.identity.subject
  );
}
/** Topics use a fixed namespace and a one-way tenant binding; identifiers never become metric labels. */
export function tenantKey(context: VerifiedTenantContext): string {
  return createHash('sha256')
    .update(JSON.stringify([context.identity.issuer, context.tenantId]))
    .digest('hex');
}
