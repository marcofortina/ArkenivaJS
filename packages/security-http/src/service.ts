// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { within } from '@arkenivajs/core/support';
import { Tokens } from '@fastify/csrf';
import type { OperationOptions } from '@arkenivajs/core';
import { KitError } from '@arkenivajs/core';
import type {
  SecurityHttpService,
  HttpSecurityPolicy,
  HttpSecurityRequest,
  IdentitySubject,
} from './contracts.js';
import type { Settings } from './settings.js';
import type { ProviderTask } from './provider-task.js';
import { observation } from './observation.js';
import type { Observers } from './observation.js';
import type { Call } from './runtime.js';
import { runtime } from './runtime.js';
import { fields, text, origin, failure } from './validation.js';
import { headerPolicy } from './headers.js';

const lifetime = 900000,
  namespace = 'arkenivajs.security-http.csrf.v1';
export const tokenOptions = (key: Buffer) => ({
  algorithm: 'sha256',
  saltLength: 16,
  secretLength: 32,
  validity: lifetime,
  userInfo: true as const,
  hmacKey: key,
});
export function tokenParts(input: unknown) {
  const value = text(input, 384),
    parts = value.split('.');
  if (
    parts.length !== 3 ||
    parts[0] !== 'v1' ||
    !/^[A-Za-z0-9_-]{43}$/.test(parts[1]!) ||
    Buffer.from(parts[1]!, 'base64url').toString('base64url') !== parts[1] ||
    !/^[A-Za-z0-9_-]{1,256}$/.test(parts[2]!)
  )
    throw failure('EK_HTTP_CSRF');
  return { nonce: parts[1]!, native: parts[2]! };
}
function digestValue(input: unknown): string {
  const value = text(input, 1024);
  if (value.length < 32 || !/^[\x21-\x7e]+$/.test(value)) throw failure('EK_HTTP_CSRF');
  return value;
}
function subject(input: IdentitySubject): readonly string[] {
  const value = fields(input, ['issuer', 'subject', 'tenant']);
  let tenant = '';
  if (value.tenant !== undefined) {
    const context = fields(value.tenant, ['tenantId', 'identity', 'verifiedAt', 'source']);
    tenant = text(context.tenantId, 256);
  }
  return [text(value.issuer, 2048), text(value.subject, 256), tenant];
}
export async function createService(
  settings: Settings,
  owner: AbortSignal,
  ready: () => boolean,
  currentRequest: () => Readonly<{ request: HttpSecurityRequest; signal: AbortSignal }> | undefined,
  setCookie: (nonce: string) => void,
  keyTask: ProviderTask,
  observers: Observers,
) {
  const initial = keyTask.load();
  let initialValue: string;
  try {
    initialValue = digestValue(
      await within(() => initial, { signal: owner, timeoutMs: settings.timeoutMs }),
    );
  } catch (cause) {
    let code: 'EK_HTTP_CSRF' | 'EK_ABORTED' | 'EK_TIMEOUT' = 'EK_HTTP_CSRF';
    try {
      if (cause instanceof KitError && (cause.code === 'EK_ABORTED' || cause.code === 'EK_TIMEOUT'))
        code = cause.code;
    } catch {
      /* Initial provider diagnostics remain private. */
    }
    throw failure(code);
  }
  const root = Buffer.from(initialValue, 'utf8');
  const tokens = Tokens(tokenOptions(root)),
    gate = runtime(settings, owner, ready, () => currentRequest()?.signal),
    observed = observation(observers);
  let policy = settings.initialPolicy;
  async function authorize(sessionId: string, action: string, call: Call) {
    if (!policy.csrfEnabled) throw failure('EK_HTTP_CSRF');
    const request = currentRequest()?.request;
    if (request && !request.secure) throw failure('EK_HTTP_CSRF');
    const identity = await settings.authority.require(
      'security-http.' + action,
      undefined,
      { sessionId, ...(request ? { request } : {}) },
      call.options(),
    );
    call.check();
    const parts = [...subject(identity), sessionId];
    const current = Buffer.from(
      digestValue(
        await settings.hmac.digest(
          'arkenivajs.security-http.native-key.v1',
          [],
          settings.keyRef,
          call.options(),
        ),
      ),
      'utf8',
    );
    try {
      if (current.length !== root.length || !timingSafeEqual(current, root))
        throw failure('EK_HTTP_CSRF');
    } finally {
      current.fill(0);
    }
    call.check();
    return digestValue(
      await settings.hmac.digest(
        'arkenivajs.security-http.owner.v1',
        parts,
        settings.keyRef,
        call.options(),
      ),
    );
  }
  async function index(binding: string, nonce: string, call: Call) {
    const value = digestValue(
      await settings.hmac.digest(
        'arkenivajs.security-http.state.v1',
        [binding, nonce],
        settings.keyRef,
        call.options(),
      ),
    );
    call.check();
    return value;
  }
  async function liveBinding(binding: string, nonce: string, call: Call): Promise<boolean> {
    const id = await index(binding, nonce, call);
    const stored = await settings.store.read(namespace, id, call.options());
    call.check();
    if (stored === null) return false;
    let row: Record<string, unknown>;
    try {
      row = fields(stored, ['kind', 'binding', 'ownerKey', 'expiresAt', 'version']);
    } catch {
      throw failure('EK_HTTP_CSRF');
    }
    if (
      row.kind !== 'csrf' ||
      row.binding !== binding ||
      row.ownerKey !== binding ||
      typeof row.expiresAt !== 'string' ||
      !Number.isFinite(Date.parse(row.expiresAt)) ||
      Date.parse(row.expiresAt) > Date.now() + lifetime + 1000
    )
      throw failure('EK_HTTP_CSRF');
    return Date.parse(row.expiresAt as string) > Date.now();
  }
  async function verify(
    context: Readonly<{ sessionId: string; origin: string }>,
    token: string,
    call: Call,
  ) {
    const ctx = fields(context, ['sessionId', 'origin']),
      sessionId = text(ctx.sessionId, 256),
      suppliedOrigin = origin(ctx.origin);
    if (!settings.origins.includes(suppliedOrigin)) throw failure('EK_HTTP_CSRF');
    const parsed = tokenParts(token),
      binding = await authorize(sessionId, 'verify', call);
    if (
      !(await liveBinding(binding, parsed.nonce, call)) ||
      !tokens.verify(parsed.nonce, parsed.native, binding)
    )
      throw failure('EK_HTTP_CSRF');
    return Object.freeze({ nonce: parsed.nonce, binding });
  }
  const service: SecurityHttpService = Object.freeze({
    installHeaders(input: HttpSecurityPolicy) {
      gate.check();
      let next: HttpSecurityPolicy;
      try {
        next = headerPolicy(input);
      } catch {
        throw failure();
      }
      if (
        (settings.routes.length && !next.csrfEnabled) ||
        (next.csrfEnabled && !settings.origins.length)
      )
        throw failure();
      policy = next;
    },
    getEffectivePolicy() {
      gate.check();
      return policy;
    },
    async csrfToken(context: Readonly<{ sessionId: string }>, options?: OperationOptions) {
      const ctx = fields(context, ['sessionId']),
        sessionId = text(ctx.sessionId, 256);
      return observed.run('issue', () =>
        gate.run(options, async (call) => {
          const binding = await authorize(sessionId, 'issue', call);
          const existing = currentRequest()?.request.cookies['__Host-arkeniva-csrf'];
          if (existing !== undefined) {
            if (
              !/^[A-Za-z0-9_-]{43}$/.test(existing) ||
              Buffer.from(existing, 'base64url').toString('base64url') !== existing
            )
              throw failure('EK_HTTP_CSRF');
            if (await liveBinding(binding, existing, call)) {
              const token = 'v1.' + existing + '.' + tokens.create(existing, binding);
              call.check();
              setCookie(existing);
              return token;
            }
          }
          const nonce = randomBytes(32).toString('base64url'),
            id = await index(binding, nonce, call),
            expiresAt = new Date(Date.now() + lifetime).toISOString();
          call.sideEffectAttempted = true;
          const receipt = await settings.store.compareAndSet(
            namespace,
            id,
            null,
            Object.freeze({ kind: 'csrf', binding, ownerKey: binding, expiresAt }),
            call.options(),
          );
          call.check();
          if (fields(receipt, ['committed', 'version']).committed !== true)
            throw failure('EK_HTTP_CSRF', true);
          const token = 'v1.' + nonce + '.' + tokens.create(nonce, binding);
          call.check();
          setCookie(nonce);
          return token;
        }),
      );
    },
    async verifyCsrf(
      context: Readonly<{ sessionId: string; origin: string }>,
      token: string,
      options?: OperationOptions,
    ) {
      const ctx = fields(context, ['sessionId', 'origin']),
        snapshot = Object.freeze({
          sessionId: text(ctx.sessionId, 256),
          origin: origin(ctx.origin),
        }),
        parsed = tokenParts(token);
      await observed.run('verify', () =>
        gate.run(options, async (call) => {
          await verify(snapshot, 'v1.' + parsed.nonce + '.' + parsed.native, call);
        }),
      );
    },
  });
  return {
    service,
    currentPolicy: () => policy,
    nativeKey: root,
    verifyCookie(
      context: Readonly<{ sessionId: string; origin: string }>,
      token: string,
      options?: OperationOptions,
    ) {
      return observed.run('verify', () =>
        gate.run(options, (call) => verify(context, token, call)),
      );
    },
    resolveSession(request: HttpSecurityRequest) {
      return gate.run(undefined, async (call) => {
        if (!settings.session) throw failure('EK_HTTP_CSRF');
        const result = fields(await settings.session.resolve(request, call.options()), [
          'sessionId',
        ]);
        call.check();
        return text(result.sessionId, 256);
      });
    },
    async close() {
      await gate.close();
      root.fill(0);
    },
  };
}
