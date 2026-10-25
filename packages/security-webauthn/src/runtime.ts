// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type {
  MfaManagementAuthorization,
  MfaSubjectContext,
  OperationOptions,
} from '@arkenivajs/core';
import { copyData, within } from '@arkenivajs/core/support';
import type { WebAuthnServiceOptions, WebAuthnPolicyAction } from './contracts.js';
import { createWebAuthnDriver } from './webauthn-driver.js';

export const policyError = () =>
  new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid or insufficient WebAuthn policy' });
export const storageError = () =>
  new KitError({ code: 'EK_MFA_STORAGE', message: 'Required MFA provider is unavailable' });

/** Read data properties without treating their presence as authentication. */
export function data(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw policyError();
  const descriptors = Object.getOwnPropertyDescriptors(value),
    result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const name of Reflect.ownKeys(descriptors)) {
    if (typeof name !== 'string' || !fields.includes(name)) throw policyError();
    const field = descriptors[name]!;
    if (!('value' in field)) throw policyError();
    result[name] = field.value;
  }
  return result;
}

export function text(value: unknown, maximum = 1024): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > maximum ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    throw policyError();
}

export function instant(value: unknown): number {
  text(value, 64);
  const at = Date.parse(value);
  if (!Number.isFinite(at) || new Date(at).toISOString() !== value) throw policyError();
  return at;
}

function property(object: object, name: string): unknown {
  if (!object || typeof object !== 'object') throw policyError();
  let current: object | null = object;
  while (current) {
    const field = Object.getOwnPropertyDescriptor(current, name);
    if (field) {
      if (!('value' in field)) throw policyError();
      return field.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  return undefined;
}

function method<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  const fn = property(object, name);
  if (typeof fn !== 'function') throw policyError();
  return fn.bind(object) as T;
}

function provider<T extends object>(
  value: T,
  methods: readonly (keyof T & string)[],
  env: string,
): T {
  const usage = property(value, 'usage');
  if (
    usage !== undefined &&
    (typeof usage !== 'string' ||
      !['production', 'test-only'].includes(usage) ||
      (env === 'production' && usage !== 'production'))
  )
    throw policyError();
  const captured: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const name of methods) captured[name] = method(value, name);
  return Object.freeze(captured) as T;
}

function subjectData(value: unknown): Record<string, unknown> {
  const subject = data(value, [
    'issuer',
    'subject',
    'primarySessionId',
    'authenticatedAt',
    'tenant',
  ]);
  for (const name of ['issuer', 'subject', 'primarySessionId']) text(subject[name]);
  instant(subject.authenticatedAt);
  let tenantId: string | undefined;
  if ('tenant' in subject) {
    const tenant = data(subject.tenant, ['tenantId', 'identity', 'source', 'verifiedAt']);
    text(tenant.tenantId, 128);
    instant(tenant.verifiedAt);
    const identity = data(tenant.identity, [
      'issuer',
      'subject',
      'audience',
      'scopes',
      'claims',
      'assurance',
    ]);
    if (
      !Object.isFrozen(subject.tenant) ||
      !Object.isFrozen(tenant.identity) ||
      identity.issuer !== subject.issuer ||
      identity.subject !== subject.subject ||
      !['oidc', 'service-identity'].includes(tenant.source as string)
    )
      throw policyError();
    tenantId = tenant.tenantId;
  }
  return { ...subject, tenantId };
}

export interface WebAuthnCall {
  readonly options: OperationOptions;
  now(): number;
  check(): void;
  call<T>(work: () => Promise<T>, kind?: 'storage' | 'policy'): Promise<T>;
}

/** Private service boundary: captured providers, bounded calls and independently verified authority. */
function captureRuntime(input: WebAuthnServiceOptions) {
  const options = data(input, [
    'rpId',
    'rpName',
    'expectedOrigins',
    'stateStore',
    'rateLimitStore',
    'evidenceStore',
    'subjectAuthority',
    'environment',
    'clock',
    'userVerification',
    'attestation',
    'challengeTtlMs',
    'passwordlessEnabled',
  ]) as unknown as WebAuthnServiceOptions;
  const environment = options.environment === undefined ? 'production' : options.environment;
  const challengeTtlMs = options.challengeTtlMs === undefined ? 300000 : options.challengeTtlMs;
  const attestation = options.attestation === undefined ? 'none' : options.attestation;
  if (
    !['production', 'development', 'test'].includes(environment) ||
    (options.clock !== undefined && environment !== 'test') ||
    (options.userVerification !== undefined && options.userVerification !== 'required') ||
    !['none', 'direct'].includes(attestation) ||
    !Number.isSafeInteger(challengeTtlMs) ||
    challengeTtlMs < 1 ||
    challengeTtlMs > 300000 ||
    (options.passwordlessEnabled !== undefined && typeof options.passwordlessEnabled !== 'boolean')
  )
    throw policyError();
  if (
    !Array.isArray(options.expectedOrigins) ||
    options.expectedOrigins.length < 1 ||
    options.expectedOrigins.length > 64
  )
    throw policyError();
  const driverSettings = copyData({
    rpId: options.rpId,
    rpName: options.rpName,
    expectedOrigins: options.expectedOrigins,
    environment,
    attestation,
  });
  const driver = createWebAuthnDriver(driverSettings);
  const ceremonyContext = createHash('sha256')
    .update(
      JSON.stringify([
        'arkenivajs-webauthn-policy-v1',
        driverSettings.rpId,
        [...driverSettings.expectedOrigins].sort(),
        'required',
        attestation,
        challengeTtlMs,
      ]),
    )
    .digest('hex');
  const clock =
    options.clock === undefined
      ? Date.now.bind(Date)
      : method<() => number>(options.clock, 'nowEpochMs');
  const now = () => {
    let value: number;
    try {
      value = clock();
      if ((value as unknown) instanceof Promise)
        void (value as unknown as Promise<unknown>).catch(() => undefined);
    } catch {
      throw policyError();
    }
    if (!Number.isSafeInteger(value) || value < 0 || value > 253402300799999) throw policyError();
    return value;
  };
  now();
  const state = provider(
    options.stateStore,
    [
      'createChallenge',
      'claimChallenge',
      'discardChallenge',
      'listCredentials',
      'getCredential',
      'getOrCreateUserHandle',
      'verifyUserHandleBinding',
      'insertCredentialIfAbsent',
      'advanceCounter',
      'revokeCredential',
    ],
    environment,
  );
  const limiter = provider(options.rateLimitStore, ['checkAndRecord'], environment);
  const evidence = provider(options.evidenceStore, ['recordOnce', 'consume'], environment);
  const authority = provider(
    options.subjectAuthority,
    ['resolveSubject', 'authorize', 'resolvePasswordlessSubject'],
    environment,
  );

  return Object.freeze({
    rpId: options.rpId,
    ceremonyContext,
    challengeTtlMs,
    attestation,
    passwordlessEnabled: options.passwordlessEnabled ?? false,
    driver,
    state,
    evidence,
    async run<T>(
      operation: OperationOptions | undefined,
      work: (call: WebAuthnCall) => Promise<T>,
    ): Promise<T> {
      const requested = data(operation === undefined ? {} : operation, ['signal', 'timeoutMs']);
      const timeoutMs = requested.timeoutMs === undefined ? 30000 : requested.timeoutMs;
      if (
        !Number.isSafeInteger(timeoutMs) ||
        (timeoutMs as number) < 1 ||
        (timeoutMs as number) > 120000
      )
        throw policyError();
      if (requested.signal !== undefined && !(requested.signal instanceof AbortSignal))
        throw policyError();
      const controller = new AbortController(),
        signal =
          requested.signal === undefined
            ? controller.signal
            : AbortSignal.any([controller.signal, requested.signal as AbortSignal]);
      const captured = Object.freeze({ signal, timeoutMs: timeoutMs as number });
      const deadline = performance.now() + captured.timeoutMs;
      let finished = false;
      const check = () => {
        if (finished || signal.aborted)
          throw new KitError({ code: 'EK_ABORTED', message: 'MFA operation aborted' });
        if (performance.now() >= deadline)
          throw new KitError({ code: 'EK_TIMEOUT', message: 'MFA operation timed out' });
      };
      const call: WebAuthnCall = {
        options: captured,
        now,
        check,
        async call(work, kind = 'storage') {
          check();
          let result;
          try {
            result = await work();
          } catch (cause) {
            check();
            if (
              kind === 'policy' &&
              cause instanceof KitError &&
              ['EK_AUTH_FORBIDDEN', 'EK_MFA_ASSURANCE_REQUIRED'].includes(cause.code)
            )
              throw new KitError({ code: cause.code, message: 'MFA operation is not authorized' });
            throw kind === 'policy' ? policyError() : storageError();
          }
          check();
          return result;
        },
      };
      try {
        check();
        return await within(() => work(call), captured);
      } catch (cause) {
        if (cause instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(cause.code))
          throw new KitError({
            code: cause.code,
            message:
              cause.code === 'EK_ABORTED' ? 'MFA operation aborted' : 'MFA operation timed out',
          });
        if (
          cause instanceof KitError &&
          [
            'EK_MFA_POLICY',
            'EK_MFA_STORAGE',
            'EK_MFA_INVALID',
            'EK_MFA_RATE_LIMIT',
            'EK_MFA_REPLAY',
            'EK_MFA_CHALLENGE_EXPIRED',
            'EK_MFA_CREDENTIAL_CONFLICT',
            'EK_MFA_COUNTER_REGRESSION',
            'EK_AUTH_FORBIDDEN',
            'EK_MFA_ASSURANCE_REQUIRED',
          ].includes(cause.code)
        )
          throw new KitError({ code: cause.code, message: 'MFA operation was not accepted' });
        throw storageError();
      } finally {
        finished = true;
        controller.abort();
      }
    },
    async resolve(candidate: MfaSubjectContext, call: WebAuthnCall): Promise<MfaSubjectContext> {
      const requested = subjectData(candidate);
      const owner = await call.call(
        () => authority.resolveSubject(candidate, call.options),
        'policy',
      );
      if (!owner || !Object.isFrozen(owner)) throw policyError();
      const actual = subjectData(owner);
      for (const key of [
        'issuer',
        'subject',
        'tenantId',
        'primarySessionId',
        'authenticatedAt',
      ] as const)
        if (requested[key] !== actual[key]) throw policyError();
      if (instant(owner.authenticatedAt) > call.now()) throw policyError();
      return owner;
    },
    async authorize(
      subject: MfaSubjectContext,
      action: WebAuthnPolicyAction,
      authorization: MfaManagementAuthorization | undefined,
      call: WebAuthnCall,
    ): Promise<void> {
      const at = call.now(),
        sensitive = ['begin-registration', 'finish-registration', 'revoke-credential'].includes(
          action,
        );
      if (sensitive && at - instant(subject.authenticatedAt) > 300000) throw policyError();
      if (action === 'revoke-credential' && authorization === undefined) throw policyError();
      if (authorization !== undefined) {
        const grant = data(authorization, ['action', 'subject', 'trustedSessionId', 'verifiedAt']);
        const verifiedAt = instant(grant.verifiedAt);
        if (
          action !== 'revoke-credential' ||
          grant.action !== 'revoke' ||
          grant.subject !== subject.subject ||
          grant.trustedSessionId !== subject.primarySessionId ||
          verifiedAt > at ||
          at - verifiedAt > 60000
        )
          throw policyError();
      }
      const result = await call.call(
        () =>
          authority.authorize(
            Object.freeze({
              action,
              subject,
              ...(authorization === undefined ? {} : { authorization }),
            }),
            call.options,
          ),
        'policy',
      );
      if (result !== undefined) throw policyError();
      const completed = call.now();
      if (
        (sensitive && completed - instant(subject.authenticatedAt) > 300000) ||
        (authorization !== undefined && completed - instant(authorization.verifiedAt) > 60000)
      )
        throw policyError();
    },
    async limit(
      action: WebAuthnPolicyAction,
      subject: MfaSubjectContext | undefined,
      call: WebAuthnCall,
    ): Promise<void> {
      const scopeKey = createHash('sha256')
        .update(
          JSON.stringify([
            'arkenivajs-webauthn-limit-v1',
            options.rpId,
            subject?.issuer ?? null,
            subject?.subject ?? null,
            subject?.tenant?.tenantId ?? null,
          ]),
        )
        .digest('hex');
      const decision = await call.call(() =>
        limiter.checkAndRecord(
          {
            scopeKey,
            operation: action,
            maxAttempts: subject === undefined ? 20 : 5,
            windowMs: 60000,
            nowMs: call.now(),
          },
          call.options,
        ),
      );
      const result = await call.call(async () => {
        const result = data(decision, ['allowed', 'retryAfterMs']);
        if (
          typeof result.allowed !== 'boolean' ||
          (result.retryAfterMs !== undefined &&
            (!Number.isSafeInteger(result.retryAfterMs) || (result.retryAfterMs as number) < 1))
        )
          throw storageError();
        return result;
      });
      if (!result.allowed)
        throw new KitError({ code: 'EK_MFA_RATE_LIMIT', message: 'MFA attempt limit reached' });
    },
    async passwordlessOwner(
      input: Parameters<typeof authority.resolvePasswordlessSubject>[0],
      call: WebAuthnCall,
    ) {
      if (!options.passwordlessEnabled) throw policyError();
      // The service invokes this only after signature/challenge/credential-owner verification.
      const owner = await call.call(
        () => authority.resolvePasswordlessSubject(Object.freeze({ ...input }), call.options),
        'policy',
      );
      const actual = data(owner, ['issuer', 'subject', 'tenantId']);
      text(actual.issuer);
      text(actual.subject);
      if (actual.tenantId !== undefined) text(actual.tenantId, 128);
      for (const key of ['issuer', 'subject', 'tenantId'] as const)
        if (actual[key] !== input[key]) throw policyError();
      return Object.freeze({
        issuer: owner.issuer,
        subject: owner.subject,
        ...(owner.tenantId === undefined ? {} : { tenantId: owner.tenantId }),
      });
    },
  });
}

/** Constructor failures contain no provider diagnostics or input values. */
export function createWebAuthnRuntime(input: WebAuthnServiceOptions) {
  try {
    return captureRuntime(input);
  } catch {
    throw policyError();
  }
}
