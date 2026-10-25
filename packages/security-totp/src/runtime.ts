// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type {
  MfaManagementAuthorization,
  MfaSubjectContext,
  OperationOptions,
} from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { TotpServiceOptions, TotpPolicyAction, TotpRecoveryProofInput } from './contracts.js';

export const policyError = () =>
  new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid or insufficient TOTP security policy' });
export const invalidProof = () =>
  new KitError({ code: 'EK_MFA_INVALID', message: 'Invalid factor proof' });
// Secret-bearing providers may echo input; retain only the fixed category at this boundary.
export const storageError = () =>
  new KitError({ code: 'EK_MFA_STORAGE', message: 'Required MFA provider is unavailable' });

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
function property(object: object, name: string): unknown {
  if (!object || typeof object !== 'object') throw policyError();
  let current: object | null = object;
  while (current) {
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) {
      if (!('value' in descriptor)) throw policyError();
      return descriptor.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  return undefined;
}
function method<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  const value = property(object, name);
  if (typeof value !== 'function') throw policyError();
  return value.bind(object) as T;
}
function component<T extends object>(
  value: T,
  methods: readonly (keyof T & string)[],
  environment: string,
): T {
  if (!value || typeof value !== 'object') throw policyError();
  const usage = property(value, 'usage');
  if (
    usage !== undefined &&
    (!['production', 'test-only'].includes(usage as string) ||
      (environment === 'production' && usage !== 'production'))
  )
    throw policyError();
  const result: Record<string, unknown> = {};
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
      (tenant.source !== 'oidc' && tenant.source !== 'service-identity')
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
    'subjectAuthority',
    'recoveryHmac',
    'stateStore',
    'rateLimitStore',
    'secretProtector',
    'evidenceStore',
    'clock',
    'periodSeconds',
    'digits',
    'driftSteps',
    'enrollmentTtlMs',
    'recoveryCodeCount',
  ]) as unknown as TotpServiceOptions;
  const environment = options.environment === undefined ? 'production' : options.environment;
  const driftSteps = options.driftSteps === undefined ? 1 : options.driftSteps,
    enrollmentTtlMs = options.enrollmentTtlMs === undefined ? 300000 : options.enrollmentTtlMs,
    recoveryCodeCount = options.recoveryCodeCount === undefined ? 10 : options.recoveryCodeCount;
  text(options.issuer, 128);
  if (
    options.issuer.trim() !== options.issuer ||
    !['production', 'development', 'test'].includes(environment) ||
    (options.periodSeconds !== undefined && options.periodSeconds !== 30) ||
    (options.digits !== undefined && options.digits !== 6) ||
    ![0, 1].includes(driftSteps) ||
    !Number.isSafeInteger(enrollmentTtlMs) ||
    enrollmentTtlMs < 1 ||
    enrollmentTtlMs > 300000 ||
    !Number.isSafeInteger(recoveryCodeCount) ||
    recoveryCodeCount < 10 ||
    recoveryCodeCount > 20 ||
    (options.clock !== undefined && environment !== 'test')
  )
    throw policyError();
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
    environment,
  );
  const limiter = component(options.rateLimitStore, ['checkAndRecord'], environment);
  const protector = component(options.secretProtector, ['seal', 'open'], environment);
  const evidence = component(options.evidenceStore, ['recordOnce', 'consume'], environment);
  const trust = component(options.subjectAuthority, ['resolveSubject', 'authorize'], environment);
  const algorithm = property(options.recoveryHmac, 'algorithm'),
    securityLevel = property(options.recoveryHmac, 'securityLevel');
  if (
    algorithm !== 'HMAC-SHA256' ||
    !['production', 'test-only'].includes(securityLevel as string) ||
    (environment === 'production' && securityLevel !== 'production')
  )
    throw policyError();
  const hmac = Object.freeze({
    createVerifier: method<TotpServiceOptions['recoveryHmac']['createVerifier']>(
      options.recoveryHmac,
      'createVerifier',
    ),
    candidateVerifiers: method<TotpServiceOptions['recoveryHmac']['candidateVerifiers']>(
      options.recoveryHmac,
      'candidateVerifiers',
    ),
  });
  const verifier = (value: unknown, input: TotpRecoveryProofInput): string => {
    if (
      typeof value !== 'string' ||
      value.length < 1 ||
      value.length > 1024 ||
      /[^\x21-\x7e]/.test(value) ||
      value.includes(input.code)
    )
      throw storageError();
    return value;
  };

  return Object.freeze({
    issuer: options.issuer,
    recoveryCodeCount,
    driftSteps,
    enrollmentTtlMs,
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
            if (
              kind === 'policy' &&
              cause instanceof KitError &&
              ['EK_AUTH_FORBIDDEN', 'EK_MFA_ASSURANCE_REQUIRED'].includes(cause.code)
            )
              throw new KitError({ code: cause.code, message: 'MFA operation is not authorized' });
            throw kind === 'policy' ? policyError() : storageError();
          }
          check();
          return value;
        },
      };
      try {
        return await within(() => work(call), captured);
      } catch (cause) {
        if (cause instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(cause.code))
          throw new KitError({
            code: cause.code,
            message:
              cause.code === 'EK_ABORTED' ? 'MFA operation aborted' : 'MFA operation timed out',
          });
        throw cause;
      } finally {
        finished = true;
        controller.abort();
      }
    },
    async resolve(subject: MfaSubjectContext, call: TotpCall): Promise<MfaSubjectContext> {
      const requested = subjectData(subject);
      const resolved = await call.call(() => trust.resolveSubject(subject, call.options), 'policy');
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
      action: TotpPolicyAction,
      authorization: MfaManagementAuthorization | undefined,
      call: TotpCall,
    ): Promise<void> {
      const at = call.now();
      const sensitive = [
        'begin-enrollment',
        'read-enrollment-qr',
        'confirm-enrollment',
        'disable',
        'generate-recovery-codes',
      ].includes(action);
      if (
        (action === 'disable' || action === 'generate-recovery-codes') &&
        authorization === undefined
      )
        throw policyError();
      if (sensitive && at - instant(subject.authenticatedAt) > 300000) throw policyError();
      if (authorization !== undefined) {
        const grant = data(authorization, ['action', 'subject', 'trustedSessionId', 'verifiedAt']);
        const time = instant(grant.verifiedAt);
        if (
          grant.action !== (action === 'generate-recovery-codes' ? 'recovery-codes' : action) ||
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
            Object.freeze({
              subject,
              action,
              ...(authorization === undefined ? {} : { authorization }),
            }),
            call.options,
          ),
        'policy',
      );
      if (permitted !== undefined) throw policyError();
      const completed = call.now();
      if (
        (sensitive && completed - instant(subject.authenticatedAt) > 300000) ||
        (authorization !== undefined && completed - instant(authorization.verifiedAt) > 60000)
      )
        throw policyError();
    },
    async recoveryVerifier(input: TotpRecoveryProofInput, call: TotpCall): Promise<string> {
      return verifier(
        await call.call(() => hmac.createVerifier(Object.freeze(input), call.options)),
        input,
      );
    },
    async recoveryCandidates(
      input: TotpRecoveryProofInput,
      call: TotpCall,
    ): Promise<readonly string[]> {
      return call.call(async () => {
        const values = await hmac.candidateVerifiers(Object.freeze(input), call.options);
        if (!Array.isArray(values)) throw storageError();
        const length = values.length;
        if (!Number.isSafeInteger(length) || length < 1 || length > 8) throw storageError();
        const result: string[] = [];
        for (let index = 0; index < length; index++) {
          const field = Object.getOwnPropertyDescriptor(values, String(index));
          if (!field || !('value' in field)) throw storageError();
          result.push(verifier(field.value, input));
        }
        if (new Set(result).size !== result.length) throw storageError();
        return Object.freeze(result);
      });
    },
  });
}
