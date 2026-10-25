// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHmac } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type {
  MfaManagementAuthorization,
  MfaSubjectContext,
  OperationOptions,
} from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { TotpServiceOptions, TotpOperation, TotpTrustPolicy } from './contracts.js';

export const policyError = () =>
  new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid or insufficient TOTP security policy' });
export const invalidProof = () =>
  new KitError({ code: 'EK_MFA_INVALID', message: 'Invalid factor proof' });
export const storageError = (cause?: unknown) =>
  new KitError({ code: 'EK_MFA_STORAGE', message: 'Required MFA provider is unavailable', cause });

/** Inspect data without executing caller-controlled accessors. Preserve authority object references. */
export function data(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw policyError();
  const descriptors = Object.getOwnPropertyDescriptors(value),
    result: Record<string, unknown> = {};
  for (const name of Reflect.ownKeys(descriptors)) {
    if (typeof name !== 'string' || !fields.includes(name)) throw policyError();
    const descriptor = descriptors[name]!;
    if (!('value' in descriptor)) throw policyError();
    result[name] = descriptor.value;
  }
  return result;
}
export function text(value: unknown, maximum = 1024): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > maximum ||
    [...value].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    throw policyError();
}
export function instant(value: unknown): number {
  text(value, 64);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw policyError();
  return parsed;
}
export function keyId(value: unknown): asserts value is string {
  text(value, 64);
  if (/[^A-Za-z0-9_-]/.test(value)) throw policyError();
}
function method<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  let current: object | null = object;
  while (current) {
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) {
      if (!('value' in descriptor) || typeof descriptor.value !== 'function') throw policyError();
      return descriptor.value.bind(object) as T;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw policyError();
}
function component<T extends object>(
  value: T,
  methods: readonly (keyof T & string)[],
  environment: string,
): T {
  if (!value || typeof value !== 'object') throw policyError();
  const usage = Object.getOwnPropertyDescriptor(value, 'usage');
  if (
    !usage ||
    !('value' in usage) ||
    !['production', 'test-only'].includes(usage.value) ||
    (environment === 'production' && usage.value !== 'production')
  )
    throw policyError();
  const result: Record<string, unknown> = { usage: usage.value };
  for (const name of methods) result[name] = method(value, name);
  return Object.freeze(result) as T;
}
function subjectData(value: unknown): Record<string, unknown> {
  const record = data(value, [
    'issuer',
    'subject',
    'tenant',
    'primarySessionId',
    'authenticatedAt',
  ]);
  for (const field of ['issuer', 'subject', 'primarySessionId']) text(record[field]);
  instant(record.authenticatedAt);
  if ('tenant' in record) {
    const tenant = data(record.tenant, ['tenantId', 'identity', 'verifiedAt', 'source']);
    text(tenant.tenantId, 128);
    instant(tenant.verifiedAt);
    const identity = data(tenant.identity, [
      'subject',
      'issuer',
      'audience',
      'scopes',
      'claims',
      'assurance',
    ]);
    if (
      !Object.isFrozen(record.tenant) ||
      !Object.isFrozen(tenant.identity) ||
      identity.subject !== record.subject ||
      identity.issuer !== record.issuer ||
      !['oidc', 'service-identity'].includes(String(tenant.source))
    )
      throw policyError();
  }
  return record;
}

export interface TotpCall {
  readonly options: OperationOptions;
  now(): number;
  check(): void;
  call<T>(work: () => Promise<T>, kind?: 'storage' | 'policy'): Promise<T>;
}

/** Capture all trusted configuration once; no request can override time or provider selection. */
export function createTotpRuntime(input: TotpServiceOptions) {
  const options = data(input, [
    'issuer',
    'environment',
    'trustPolicy',
    'recoveryCodeHmac',
    'stateStore',
    'rateLimitStore',
    'secretProtector',
    'evidenceStore',
    'clock',
    'periodSeconds',
    'digits',
    'driftSteps',
    'enrollmentTtlMs',
  ]) as unknown as TotpServiceOptions;
  text(options.issuer, 128);
  if (
    options.issuer.trim() !== options.issuer ||
    !['production', 'development', 'test'].includes(options.environment) ||
    (options.periodSeconds !== undefined && options.periodSeconds !== 30) ||
    (options.digits !== undefined && options.digits !== 6) ||
    ![0, 1].includes(options.driftSteps ?? 1) ||
    !Number.isSafeInteger(options.enrollmentTtlMs ?? 300000) ||
    (options.enrollmentTtlMs ?? 300000) < 1 ||
    (options.enrollmentTtlMs ?? 300000) > 300000 ||
    (options.clock !== undefined &&
      (typeof options.clock !== 'function' || options.environment === 'production'))
  )
    throw policyError();
  const clock = options.clock ?? Date.now.bind(Date);
  const now = () => {
    let value: number;
    try {
      value = clock();
    } catch {
      throw policyError();
    }
    if (!Number.isSafeInteger(value) || value < 0 || value > 253402300799999) throw policyError();
    return value;
  };
  now();
  const state = component(
    options.stateStore,
    [
      'createChallenge',
      'claimChallenge',
      'discardChallenge',
      'putPending',
      'getPending',
      'activatePending',
      'getFactor',
      'acceptStepIfGreater',
      'revokeFactor',
      'replaceRecoveryHashes',
      'consumeRecoveryHash',
    ],
    options.environment,
  );
  const limiter = component(options.rateLimitStore, ['checkAndRecord'], options.environment);
  const protector = component(options.secretProtector, ['seal', 'open'], options.environment);
  const evidence = component(options.evidenceStore, ['recordOnce', 'consume'], options.environment);
  const trust = component(
    options.trustPolicy,
    ['resolveSubject', 'authorize'],
    options.environment,
  );
  const hmac = data(options.recoveryCodeHmac, ['algorithm', 'keyProvider']);
  if (hmac.algorithm !== 'HMAC-SHA256') throw policyError();
  const keys = component(
    hmac.keyProvider as TotpServiceOptions['recoveryCodeHmac']['keyProvider'],
    ['currentKeyId', 'resolveKey'],
    options.environment,
  );

  return Object.freeze({
    issuer: options.issuer,
    driftSteps: options.driftSteps ?? 1,
    enrollmentTtlMs: options.enrollmentTtlMs ?? 300000,
    state,
    limiter,
    protector,
    evidence,
    async run<T>(
      operation: OperationOptions | undefined,
      work: (call: TotpCall) => Promise<T>,
    ): Promise<T> {
      const timeoutMs = operation?.timeoutMs ?? 30000;
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw policyError();
      const controller = new AbortController(),
        signal = operation?.signal
          ? AbortSignal.any([controller.signal, operation.signal])
          : controller.signal;
      const deadline = performance.now() + timeoutMs;
      let finished = false;
      const check = () => {
        if (finished || signal.aborted)
          throw new KitError({ code: 'EK_ABORTED', message: 'MFA operation aborted' });
        if (performance.now() >= deadline)
          throw new KitError({ code: 'EK_TIMEOUT', message: 'MFA operation timed out' });
      };
      const captured = Object.freeze({ timeoutMs, signal });
      const call: TotpCall = {
        options: captured,
        now,
        check,
        async call(work, kind = 'storage') {
          check();
          let value;
          try {
            value = await work();
          } catch (cause) {
            check();
            if (cause instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(cause.code))
              throw cause;
            throw kind === 'policy' ? policyError() : storageError(cause);
          }
          check();
          return value;
        },
      };
      try {
        return await within(() => work(call), captured);
      } finally {
        finished = true;
        controller.abort();
      }
    },
    async resolve(
      subject: MfaSubjectContext,
      operation: TotpOperation,
      call: TotpCall,
    ): Promise<MfaSubjectContext> {
      const requested = subjectData(subject);
      const resolved = await call.call(
        () => trust.resolveSubject(subject, operation, call.options),
        'policy',
      );
      if (!resolved || !Object.isFrozen(resolved))
        throw new KitError({
          code: 'EK_AUTH_FORBIDDEN',
          message: 'Authenticated MFA subject is required',
        });
      const actual = subjectData(resolved);
      for (const field of ['issuer', 'subject', 'primarySessionId', 'authenticatedAt', 'tenant'])
        if (actual[field] !== requested[field]) throw policyError();
      if (instant(resolved.authenticatedAt) > call.now()) throw policyError();
      return resolved;
    },
    async authorize(
      subject: MfaSubjectContext,
      action: Parameters<TotpTrustPolicy['authorize']>[1]['action'],
      authorization: MfaManagementAuthorization | undefined,
      call: TotpCall,
    ): Promise<void> {
      const at = call.now();
      if ((action === 'disable' || action === 'recovery-codes') && authorization === undefined)
        throw policyError();
      if (at - instant(subject.authenticatedAt) > 300000) throw policyError();
      if (authorization !== undefined) {
        const grant = data(authorization, ['action', 'subject', 'trustedSessionId', 'verifiedAt']);
        const time = instant(grant.verifiedAt);
        if (
          grant.action !== action ||
          grant.subject !== subject.subject ||
          grant.trustedSessionId !== subject.primarySessionId ||
          time > at ||
          at - time > 60000
        )
          throw policyError();
      }
      const permitted = await call.call(
        () =>
          trust.authorize(
            subject,
            { action, ...(authorization === undefined ? {} : { authorization }) },
            call.options,
          ),
        'policy',
      );
      if (permitted !== true) throw policyError();
      const completed = call.now();
      if (
        completed - instant(subject.authenticatedAt) > 300000 ||
        (authorization !== undefined && completed - instant(authorization.verifiedAt) > 60000)
      )
        throw policyError();
    },
    async activeRecoveryKey(call: TotpCall): Promise<string> {
      const version = await call.call(() => keys.currentKeyId(call.options));
      keyId(version);
      return version;
    },
    async recoveryHash(
      subject: MfaSubjectContext,
      version: string,
      code: string,
      call: TotpCall,
    ): Promise<string> {
      keyId(version);
      const provided = await call.call(() => keys.resolveKey(version, call.options));
      if (!(provided instanceof Uint8Array) || provided.byteLength < 32 || provided.byteLength > 64)
        throw storageError();
      const owned = Buffer.from(provided);
      try {
        call.check();
        const digest = createHmac('sha256', owned)
          .update(
            JSON.stringify([
              'arkenivajs-totp-recovery-v1',
              version,
              subject.issuer,
              subject.subject,
              subject.tenant?.tenantId ?? null,
              code,
            ]),
          )
          .digest('hex');
        call.check();
        return version + ':' + digest;
      } catch (cause) {
        if (cause instanceof KitError) throw cause;
        throw storageError(cause);
      } finally {
        owned.fill(0);
      }
    },
  });
}
