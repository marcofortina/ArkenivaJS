// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  randomInt,
} from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import type { Logger, Telemetry, OperationOptions } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type {
  PasswordService,
  PasswordPolicy,
  IdentitySubject,
  PasswordHash,
  ResetIssue,
} from './contracts.js';
import { createKdf, inspectHash } from './kdf.js';
import { runtime } from './runtime.js';
import type { Settings, Call } from './runtime.js';
import {
  binding,
  data,
  failure,
  id,
  instant,
  invalid,
  passwordPolicy,
  plaintext,
  subject,
  text,
} from './validation.js';

const resets = 'password.resets.v1',
  owners = 'password.owners.v1',
  budgets = 'password.budgets.v1';
const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength',
)!.get!;
const backing = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'buffer',
)!.get!;
interface ResetState {
  readonly id: string;
  readonly ownerKey: string;
  readonly subject: IdentitySubject;
  readonly expiresAt: string;
  readonly keyVersion: string;
  readonly digest: string;
  readonly version: string;
}
const acknowledged = (input: unknown): boolean => {
  try {
    const value = data(input, ['committed', 'version']);
    if (typeof value.committed !== 'boolean') throw invalid();
    if (value.version !== undefined) text(value.version, 256);
    return value.committed;
  } catch {
    throw failure('EK_PASSWORD_RESET');
  }
};
function decode(input: unknown, resetId: string): ResetState {
  try {
    const row = data(input, [
      'kind',
      'id',
      'ownerKey',
      'subject',
      'expiresAt',
      'keyVersion',
      'digest',
      'version',
    ]);
    if (row.kind !== 'password-reset-v1' || row.id !== resetId) throw invalid();
    id(row.id);
    text(row.ownerKey, 64);
    text(row.version, 256);
    text(row.keyVersion, 256);
    if (
      !/^[a-f0-9]{64}$/.test(row.ownerKey) ||
      typeof row.digest !== 'string' ||
      !/^[a-f0-9]{64}$/.test(row.digest)
    )
      throw invalid();
    return freezeData({
      id: row.id,
      ownerKey: row.ownerKey,
      version: row.version,
      subject: subject(row.subject),
      expiresAt: instant(row.expiresAt),
      keyVersion: row.keyVersion,
      digest: row.digest,
    });
  } catch {
    throw failure('EK_PASSWORD_RESET');
  }
}
const ownerParts = (owner: IdentitySubject) => [
  owner.issuer,
  owner.subject,
  owner.tenant?.tenantId ?? '',
];
function minimal(owner: IdentitySubject): IdentitySubject {
  return freezeData({
    issuer: owner.issuer,
    subject: owner.subject,
    ...(owner.tenant
      ? {
          tenant: {
            ...owner.tenant,
            identity: {
              issuer: owner.issuer,
              subject: owner.subject,
              audience: [],
              scopes: [],
              claims: {},
            },
          },
        }
      : {}),
  });
}

/** No reset acknowledgement can precede the application's atomic credential transition. */
export function createService(settings: Settings, logger: Logger, telemetry?: Telemetry) {
  const run = runtime(settings),
    kdf = createKdf(settings.policy),
    technicalOwner = createHash('sha256')
      .update('arkenivajs.password.technical-budget.v1')
      .digest('hex');
  let active = false;
  const check = () => {
    if (!active) throw failure('EK_RESOURCE_CLOSED');
  };
  async function withSecret<T>(
    call: Call,
    work: (material: Buffer, version: string) => T,
  ): Promise<T> {
    let material: Buffer | undefined;
    try {
      const raw = await call.step('EK_PASSWORD_RESET', (options) =>
          settings.getSecret(settings.keyRef, options),
        ),
        value = data(raw, ['bytes', 'keyVersion', 'expiresAt']);
      text(value.keyVersion, 256);
      if (value.expiresAt !== undefined && Date.parse(instant(value.expiresAt)) <= Date.now())
        throw invalid();
      if (
        !(value.bytes instanceof Uint8Array) ||
        backing.call(value.bytes) instanceof SharedArrayBuffer
      )
        throw invalid();
      const length: number = byteLength.call(value.bytes);
      if (length < 32 || length > 4096) throw invalid();
      material = Buffer.alloc(length);
      Uint8Array.prototype.set.call(material, value.bytes);
      return work(material, value.keyVersion);
    } catch {
      call.check();
      throw failure('EK_PASSWORD_RESET');
    } finally {
      material?.fill(0);
    }
  }
  const mac = (key: Buffer, domain: string, parts: readonly string[]) =>
    createHmac('sha256', key)
      .update(JSON.stringify([domain, parts]))
      .digest('hex');
  const read = async (resetId: string, call: Call) => {
    const value = await call.step('EK_PASSWORD_RESET', (options) =>
      settings.store.read(resets, resetId, options),
    );
    return value === null ? null : decode(value, resetId);
  };
  async function authorize(
    action: string,
    hint: IdentitySubject,
    call: Call,
    resetId: string,
    authorization?: IdentitySubject,
  ) {
    const result = await call.step('EK_PASSWORD_RESET', (options) =>
      settings.require(
        action,
        hint,
        Object.freeze({
          ...(hint.tenant ? { tenant: hint.tenant } : {}),
          resetId,
          ...(authorization ? { authorization } : {}),
        }),
        options,
      ),
    );
    try {
      const canonical = subject(result);
      if (binding(canonical) !== binding(hint)) throw invalid();
      return canonical;
    } catch {
      throw failure('EK_PASSWORD_RESET');
    }
  }
  async function reserve(kind: 'reset' | 'kdf', call: Call) {
    const window = kind === 'reset' ? 3600000 : 60000,
      maximum = kind === 'reset' ? settings.maxResetAttemptsPerHour : 1000,
      bucket = Math.floor(Date.now() / window),
      key = kind + ':' + bucket;
    for (let attempt = 0; attempt < 8; attempt++) {
      const previous = await call.step('EK_PASSWORD_RESET', (options) =>
        settings.store.read(budgets, key, options),
      );
      let count = 0,
        expected: string | null = null;
      if (previous !== null) {
        const row = data(previous, ['kind', 'ownerKey', 'bucket', 'count', 'expiresAt', 'version']);
        if (
          row.kind !== kind ||
          row.ownerKey !== technicalOwner ||
          row.bucket !== bucket ||
          !Number.isSafeInteger(row.count) ||
          (row.count as number) < 0 ||
          (row.count as number) > maximum ||
          Date.parse(instant(row.expiresAt)) !== (bucket + 2) * window
        )
          throw failure('EK_PASSWORD_RESET');
        text(row.version, 256);
        expected = row.version;
        count = row.count as number;
      }
      if (count >= maximum) throw failure('EK_BACKEND_UNAVAILABLE');
      if (
        acknowledged(
          await call.step('EK_PASSWORD_RESET', (options) =>
            settings.store.compareAndSet(
              budgets,
              key,
              expected,
              {
                kind,
                ownerKey: technicalOwner,
                bucket,
                count: count + 1,
                expiresAt: new Date((bucket + 2) * window).toISOString(),
              },
              options,
            ),
          ),
        )
      )
        return;
      await call.step('EK_PASSWORD_RESET', (options) => delay(randomInt(1, 4), undefined, options));
    }
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
  async function breach(plain: string, policy: Readonly<Required<PasswordPolicy>>, call: Call) {
    if (!policy.blockBreachedPasswords) return;
    if (!settings.lookup) throw failure('EK_PASSWORD_POLICY');
    const bytes = plaintext(plain, policy.minLength);
    let digest: string;
    try {
      digest = createHash('sha1').update(bytes).digest('hex').toUpperCase();
    } finally {
      bytes.fill(0);
    }
    const results = await call.step('EK_PASSWORD_POLICY', (options) =>
      settings.lookup!(digest.slice(0, 5), options),
    );
    if (
      !Array.isArray(results) ||
      results.length > 20000 ||
      Reflect.ownKeys(results).length !== results.length + 1
    )
      throw failure('EK_PASSWORD_POLICY');
    const target = Buffer.from(digest.slice(5), 'ascii'),
      seen = new Set<string>();
    try {
      let breached = false;
      for (let index = 0; index < results.length; index++) {
        if (index % 128 === 0) call.check();
        const entry = Object.getOwnPropertyDescriptor(results, String(index));
        if (!entry || !('value' in entry)) throw failure('EK_PASSWORD_POLICY');
        const row = data(entry.value, ['suffix', 'count']);
        if (
          typeof row.suffix !== 'string' ||
          !/^[A-F0-9]{35}$/.test(row.suffix) ||
          !Number.isSafeInteger(row.count) ||
          (row.count as number) < 0 ||
          seen.has(row.suffix)
        )
          throw failure('EK_PASSWORD_POLICY');
        seen.add(row.suffix);
        const candidate = Buffer.from(row.suffix, 'ascii');
        // Compare the complete odd-length suffix without dropping its last nibble.
        const match = timingSafeEqual(candidate, target);
        candidate.fill(0);
        breached ||= match && (row.count as number) > 0;
      }
      if (breached) throw failure('EK_PASSWORD_POLICY');
    } finally {
      target.fill(0);
    }
  }
  function operation<T>(
    name: string,
    options: OperationOptions | undefined,
    write: boolean,
    work: (call: Call) => Promise<T>,
  ) {
    check();
    let execution: Promise<T> | undefined;
    const once = () =>
      (execution ??= (async () => {
        let outcome = 'error';
        const started = performance.now();
        try {
          const result = await run.run(options, write, work);
          outcome = 'ok';
          return result;
        } finally {
          try {
            logger.info('Password operation completed', { operation: name, outcome });
          } catch {
            /* Diagnostics contain no credential inputs. */
          }
          try {
            telemetry?.addCounter('password.' + name + '.completed.' + outcome, 1);
            telemetry?.recordHistogram(
              'password.' + name + '.duration',
              performance.now() - started,
            );
          } catch {
            /* Observation never grants a reset. */
          }
        }
      })());
    try {
      if (telemetry)
        void Promise.resolve(telemetry.withSpan('password.' + name, once)).catch(() => undefined);
    } catch {
      /* Execute exactly once even if an observer fails. */
    }
    return once();
  }
  const service = Object.freeze<PasswordService>({
    async hash(plain, input, options) {
      const policy = passwordPolicy(input, settings.policy);
      plaintext(plain, policy.minLength).fill(0);
      return operation('hash', options, false, async (call) => {
        await reserve('kdf', call);
        await breach(plain, policy, call);
        return kdf.hash(plain, policy, call);
      });
    },
    async verify(plain, stored, options) {
      // Snapshot once before asynchronous work; later caller mutations cannot change the checked PHC.
      const value = data(stored, ['scheme', 'phc']);
      inspectHash(value);
      plaintext(plain).fill(0);
      const captured = Object.freeze({ scheme: value.scheme, phc: value.phc }) as PasswordHash;
      return operation('verify', options, false, async (call) => {
        await reserve('kdf', call);
        const result = await kdf.verify(plain, captured, call);
        try {
          telemetry?.addCounter(
            'password.verify.result.' + (result.valid ? 'accepted' : 'denied'),
            1,
          );
        } catch {
          /* Observation cannot change password verification. */
        }
        return result;
      });
    },
    needsRehash(stored) {
      check();
      return kdf.needsRehash(stored);
    },
    async createReset(input, authorization, options) {
      const target = subject(input),
        actor = subject(authorization),
        resetId = randomUUID();
      return operation('create_reset', options, true, async (call) => {
        await reserve('reset', call);
        const by = await authorize('password.reset_authorize', actor, call, resetId),
          owner = await authorize('password.create_reset', target, call, resetId, by),
          secret = randomBytes(32),
          raw = secret.toString('base64url'),
          expiresAt = new Date(Date.now() + settings.resetTtlMs).toISOString();
        secret.fill(0);
        const proof = await withSecret(call, (key, version) => ({
            keyVersion: version,
            ownerKey: mac(key, 'arkenivajs.password.owner.v1', ownerParts(owner)),
            digest: mac(key, 'arkenivajs.password.reset.v1', [
              ...ownerParts(owner),
              resetId,
              expiresAt,
              version,
              raw,
            ]),
          })),
          prior = await call.step('EK_PASSWORD_RESET', (opts) =>
            settings.store.read(owners, proof.ownerKey, opts),
          );
        let expected: string | null = null,
          old: ResetState | null = null;
        if (prior !== null) {
          const row = data(prior, ['kind', 'ownerKey', 'resetId', 'expiresAt', 'version']);
          if (row.kind !== 'password-owner-v1' || row.ownerKey !== proof.ownerKey)
            throw failure('EK_PASSWORD_RESET');
          id(row.resetId);
          text(row.version, 256);
          instant(row.expiresAt);
          expected = row.version;
          old = await read(row.resetId, call);
          if (old && (old.ownerKey !== proof.ownerKey || binding(old.subject) !== binding(owner)))
            throw failure('EK_PASSWORD_RESET');
        }
        if (
          !acknowledged(
            await call.step('EK_PASSWORD_RESET', (opts) =>
              settings.store.atomicBatch(
                [
                  {
                    namespace: owners,
                    id: proof.ownerKey,
                    ownerKey: proof.ownerKey,
                    expectedVersion: expected,
                    next: {
                      kind: 'password-owner-v1',
                      ownerKey: proof.ownerKey,
                      resetId,
                      expiresAt,
                    },
                  },
                  {
                    namespace: resets,
                    id: resetId,
                    ownerKey: proof.ownerKey,
                    expectedVersion: null,
                    next: {
                      kind: 'password-reset-v1',
                      id: resetId,
                      subject: minimal(owner),
                      expiresAt,
                      ...proof,
                    },
                  },
                  ...(old
                    ? [
                        {
                          namespace: resets,
                          id: old.id,
                          ownerKey: proof.ownerKey,
                          expectedVersion: old.version,
                          next: null,
                        },
                      ]
                    : []),
                ],
                opts,
              ),
            ),
          )
        )
          throw failure('EK_PASSWORD_RESET');
        return Object.freeze({
          requestId: resetId,
          value: 'pr1.' + resetId + '.' + raw,
          expiresAt,
        }) satisfies ResetIssue;
      });
    },
    async consumeReset(token, newPassword, options) {
      text(token, 4096);
      plaintext(newPassword, settings.policy.minLength).fill(0);
      const parts =
        /^pr1\.([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\.([A-Za-z0-9_-]{43})$/.exec(
          token,
        );
      return operation('consume_reset', options, true, async (call) => {
        await reserve('reset', call);
        const resetId = parts?.[1] ?? '00000000-0000-4000-8000-000000000000',
          row = await read(resetId, call);
        const proof = await withSecret(call, (key, version) => {
          const actual = mac(
            key,
            'arkenivajs.password.reset.v1',
            row
              ? [
                  ...ownerParts(row.subject),
                  row.id,
                  row.expiresAt,
                  row.keyVersion,
                  parts?.[2] ?? 'invalid',
                ]
              : ['negative', resetId],
          );
          return (
            timingSafeEqual(
              Buffer.from(actual, 'hex'),
              Buffer.from(row?.digest ?? '0'.repeat(64), 'hex'),
            ) &&
            row?.keyVersion === version &&
            row.ownerKey === mac(key, 'arkenivajs.password.owner.v1', ownerParts(row.subject))
          );
        });
        if (!parts || !row || !proof || Date.parse(row.expiresAt) <= Date.now())
          throw failure('EK_PASSWORD_RESET');
        const owner = await authorize('password.consume_reset', row.subject, call, row.id);
        await breach(newPassword, settings.policy, call);
        const replacement = await kdf.hash(newPassword, undefined, call);
        if (
          !acknowledged(
            await call.step('EK_PASSWORD_RESET', (opts) =>
              settings.commitReset(
                Object.freeze({
                  subject: owner,
                  reset: Object.freeze({
                    namespace: resets,
                    id: row.id,
                    version: row.version,
                    ownerKey: row.ownerKey,
                  }),
                  replacement,
                }),
                opts,
              ),
            ),
          )
        )
          throw failure('EK_PASSWORD_RESET');
        if (await read(row.id, call)) throw failure('EK_PASSWORD_RESET');
      });
    },
  });
  return {
    service,
    async bootstrap(signal: AbortSignal) {
      await run.run({ signal }, false, async (call) => {
        await withSecret(call, () => undefined);
        await kdf.bootstrap(call);
      });
      active = true;
    },
    close() {
      active = false;
      run.close();
      kdf.close();
    },
  };
}
