// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes, randomUUID, randomInt } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import type { Identity, Logger, OperationOptions, Telemetry, MfaAssurance } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type {
  IdentitySubject,
  SessionAuthentication,
  SessionPolicy,
  SessionIssue,
  SessionIdentity,
  SessionService,
  SecurityAtomicMutation,
} from './contracts.js';
import type { Call, Settings } from './runtime.js';
import { runtime } from './runtime.js';
import {
  binding,
  data,
  failure,
  id,
  identity,
  instant,
  invalid,
  policy,
  subject,
  text,
} from './validation.js';

const records = 'sessions.records.v1',
  guards = 'sessions.owners.v1',
  epochs = 'sessions.epochs.v1',
  attempts = 'sessions.attempts.v1',
  domain = 'arkenivajs.sessions.verifier.v1';
const ownerParts = (owner: IdentitySubject) => [
  owner.issuer,
  owner.subject,
  owner.tenant?.tenantId ?? '',
];
interface State {
  readonly id: string;
  readonly ownerKey: string;
  readonly version: string;
  readonly identity: Identity;
  readonly subject: IdentitySubject;
  readonly policy: SessionPolicy;
  readonly epoch: number;
  readonly authenticatedAt: string;
  readonly assuredAt?: string;
  readonly createdAt: string;
  readonly lastSeenAt: string;
  readonly absoluteExpiresAt: string;
  readonly expiresAt: string;
  readonly digest: string;
}
function acknowledged(input: unknown): boolean {
  try {
    const receipt = data(input, ['committed', 'version']);
    if (typeof receipt.committed !== 'boolean') throw invalid();
    if (receipt.version !== undefined) text(receipt.version, 256);
    return receipt.committed;
  } catch {
    throw failure('EK_SESSION_STORE');
  }
}
function safeEpoch(input: unknown): number {
  if (!Number.isSafeInteger(input) || (input as number) < 0) throw failure('EK_SESSION_STORE');
  return input as number;
}
function decode(input: unknown, keyId: string, settings: Settings): State {
  try {
    const value = data(input, [
      'kind',
      'id',
      'ownerKey',
      'version',
      'identity',
      'subject',
      'policy',
      'epoch',
      'authenticatedAt',
      'assuredAt',
      'createdAt',
      'lastSeenAt',
      'absoluteExpiresAt',
      'expiresAt',
      'digest',
    ]);
    if (value.kind !== 'session-v1' || value.id !== keyId) throw invalid();
    id(value.id);
    text(value.ownerKey, 64);
    text(value.version, 256);
    text(value.digest, 2048);
    if (!/^[a-f0-9]{64}$/.test(value.ownerKey)) throw invalid();
    const captured = identity(value.identity),
      owner = subject(value.subject),
      grant = policy(value.policy, settings.maxSessions),
      epoch = safeEpoch(value.epoch),
      authenticatedAt = instant(value.authenticatedAt),
      createdAt = instant(value.createdAt),
      lastSeenAt = instant(value.lastSeenAt),
      absoluteExpiresAt = instant(value.absoluteExpiresAt),
      expiresAt = instant(value.expiresAt),
      assuredAt = value.assuredAt === undefined ? undefined : instant(value.assuredAt);
    if (
      captured.issuer !== owner.issuer ||
      captured.subject !== owner.subject ||
      Date.parse(authenticatedAt) > Date.parse(createdAt) ||
      Date.parse(lastSeenAt) < Date.parse(createdAt) ||
      Date.parse(absoluteExpiresAt) !== Date.parse(createdAt) + grant.absoluteTtlMs ||
      Date.parse(expiresAt) !==
        Math.min(Date.parse(absoluteExpiresAt), Date.parse(lastSeenAt) + grant.idleTtlMs) ||
      (assuredAt !== undefined &&
        (Date.parse(assuredAt) < Date.parse(authenticatedAt) ||
          Date.parse(assuredAt) > Date.parse(createdAt))) ||
      (captured.assurance !== 'single-factor') !== (assuredAt !== undefined)
    )
      throw invalid();
    return freezeData({
      id: value.id,
      ownerKey: value.ownerKey,
      version: value.version,
      identity: captured,
      subject: owner,
      policy: grant,
      epoch,
      authenticatedAt,
      ...(assuredAt ? { assuredAt } : {}),
      createdAt,
      lastSeenAt,
      absoluteExpiresAt,
      expiresAt,
      digest: value.digest,
    });
  } catch {
    throw failure('EK_SESSION_STORE');
  }
}
function macParts(state: Omit<State, 'version' | 'digest'>, secret: string): readonly string[] {
  return [
    ...ownerParts(state.subject),
    state.id,
    secret,
    String(state.epoch),
    state.authenticatedAt,
    state.assuredAt ?? '',
    state.identity.assurance ?? 'single-factor',
    state.createdAt,
    state.lastSeenAt,
    state.absoluteExpiresAt,
    state.expiresAt,
    String(state.policy.absoluteTtlMs),
    String(state.policy.idleTtlMs),
    String(state.policy.maxConcurrentSessions),
    state.policy.cookieSameSite ?? 'lax',
  ];
}
function hint(owner: IdentitySubject): IdentitySubject {
  return freezeData({
    issuer: owner.issuer,
    subject: owner.subject,
    ...(owner.tenant
      ? {
          tenant: {
            tenantId: owner.tenant.tenantId,
            verifiedAt: owner.tenant.verifiedAt,
            source: owner.tenant.source,
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
function identityHint(value: Identity): Identity {
  return Object.freeze({
    issuer: value.issuer,
    subject: value.subject,
    audience: Object.freeze([]),
    scopes: Object.freeze([]),
    claims: Object.freeze({}),
    assurance: value.assurance ?? 'single-factor',
  });
}
export function createService(settings: Settings, logger: Logger, telemetry?: Telemetry) {
  const run = runtime(settings);
  let dummy: string | undefined, rateOwner: string | undefined;
  async function digest(label: string, parts: readonly string[], call: Call) {
    const result = await call.step('EK_SESSION_STORE', (options) =>
      settings.hmac.digest(label, Object.freeze([...parts]), settings.keyRef, options),
    );
    try {
      text(result, 2048);
      return result;
    } catch {
      throw failure('EK_SESSION_STORE');
    }
  }
  const ownerIndex = async (owner: IdentitySubject, call: Call) =>
    createHash('sha256')
      .update(await digest('arkenivajs.sessions.owner.v1', ownerParts(owner), call))
      .digest('hex');
  async function currentEpoch(ownerKey: string, call: Call) {
    return safeEpoch(
      await call.step('EK_SESSION_STORE', (options) =>
        settings.store.currentOwnerEpoch(epochs, ownerKey, options),
      ),
    );
  }
  async function requireEpoch(state: Pick<State, 'ownerKey' | 'epoch'>, call: Call) {
    if ((await currentEpoch(state.ownerKey, call)) !== state.epoch)
      throw failure('EK_SESSION_REVOKED');
  }
  async function read(keyId: string, call: Call) {
    const result = await call.step('EK_SESSION_STORE', (options) =>
      settings.store.read(records, keyId, options),
    );
    return result === null ? null : decode(result, keyId, settings);
  }
  async function authorize(
    action: string,
    owner: IdentitySubject | undefined,
    call: Call,
    sessionId?: string,
    grant?: SessionPolicy,
    assurance?: MfaAssurance,
  ) {
    const result = await call.step('EK_SESSION_INVALID', (options) =>
      settings.require(
        action,
        owner,
        Object.freeze({
          ...(owner?.tenant ? { tenant: owner.tenant } : {}),
          ...(sessionId ? { sessionId } : {}),
          ...(grant ? { sessionPolicy: grant } : {}),
          ...(assurance ? { assurance } : {}),
        }),
        options,
      ),
    );
    try {
      const canonical = subject(result);
      if (owner && binding(canonical) !== binding(owner)) throw invalid();
      return canonical;
    } catch {
      throw failure();
    }
  }
  async function resolve(
    input: Identity,
    operation: 'create' | 'validate' | 'renew',
    sessionId: string,
    call: Call,
    previous?: State,
  ): Promise<SessionAuthentication> {
    const result = await call.step('EK_SESSION_INVALID', (options) =>
      settings.resolveIdentity(
        input,
        Object.freeze({
          operation,
          sessionId,
          ...(operation === 'renew' && previous ? { previousSessionId: previous.id } : {}),
        }),
        options,
      ),
    );
    try {
      const value = data(result, ['identity', 'subject', 'authenticatedAt', 'assuredAt']),
        canonical = identity(value.identity),
        owner = subject(value.subject),
        authenticatedAt = instant(value.authenticatedAt),
        assuredAt = value.assuredAt === undefined ? undefined : instant(value.assuredAt);
      if (
        canonical.issuer !== input.issuer ||
        canonical.subject !== input.subject ||
        canonical.issuer !== owner.issuer ||
        canonical.subject !== owner.subject ||
        Date.parse(authenticatedAt) > Date.now() ||
        (assuredAt !== undefined &&
          (Date.parse(assuredAt) > Date.now() ||
            Date.parse(assuredAt) < Date.parse(authenticatedAt))) ||
        (canonical.assurance !== 'single-factor') !== (assuredAt !== undefined)
      )
        throw invalid();
      if (
        previous &&
        (binding(owner) !== binding(previous.subject) ||
          authenticatedAt !== previous.authenticatedAt ||
          assuredAt !== previous.assuredAt ||
          canonical.assurance !== previous.identity.assurance)
      )
        throw invalid();
      return freezeData({
        identity: canonical,
        subject: owner,
        authenticatedAt,
        ...(assuredAt ? { assuredAt } : {}),
      });
    } catch {
      throw failure();
    }
  }
  async function reserve(call: Call, ownerKey = rateOwner, maximum = 10000, bucket = 'verify') {
    if (!ownerKey) throw failure('EK_RESOURCE_CLOSED');
    const minute = Math.floor(Date.now() / 60000),
      key = bucket + '-' + ownerKey + ':' + minute;
    for (let attempt = 0; attempt < 8; attempt++) {
      const before = await call.step('EK_SESSION_STORE', (options) =>
        settings.store.read(attempts, key, options),
      );
      let expected: string | null = null,
        count = 0;
      if (before !== null)
        try {
          const value = data(before, [
            'kind',
            'ownerKey',
            'version',
            'minute',
            'count',
            'expiresAt',
          ]);
          text(value.version, 256);
          if (
            value.kind !== 'session-attempts-v1' ||
            value.ownerKey !== ownerKey ||
            value.minute !== minute ||
            !Number.isSafeInteger(value.count) ||
            (value.count as number) < 1 ||
            (value.count as number) > maximum ||
            instant(value.expiresAt) !== new Date((minute + 2) * 60000).toISOString()
          )
            throw invalid();
          expected = value.version;
          count = value.count as number;
        } catch {
          throw failure('EK_SESSION_STORE');
        }
      if (count >= maximum) throw failure();
      const receipt = await call.step('EK_SESSION_STORE', (options) =>
        settings.store.compareAndSet(
          attempts,
          key,
          expected,
          {
            kind: 'session-attempts-v1',
            ownerKey,
            minute,
            count: count + 1,
            expiresAt: new Date((minute + 2) * 60000).toISOString(),
          },
          options,
        ),
      );
      if (acknowledged(receipt)) return;
      if (attempt < 7)
        await call.step('EK_SESSION_STORE', (options) =>
          delay(randomInt(1, 4), undefined, options),
        );
    }
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
  async function guard(ownerKey: string, call: Call): Promise<SecurityAtomicMutation> {
    const previous = await call.step('EK_SESSION_STORE', (options) =>
      settings.store.read(guards, ownerKey, options),
    );
    let expectedVersion: string | null = null;
    if (previous !== null)
      try {
        const value = data(previous, ['kind', 'ownerKey', 'version', 'nonce']);
        if (value.kind !== 'session-owner-v1' || value.ownerKey !== ownerKey) throw invalid();
        text(value.version, 256);
        id(value.nonce);
        expectedVersion = value.version;
      } catch {
        throw failure('EK_SESSION_STORE');
      }
    return {
      namespace: guards,
      id: ownerKey,
      ownerKey,
      expectedVersion,
      next: Object.freeze({ kind: 'session-owner-v1', ownerKey, nonce: randomUUID() }),
    };
  }
  async function batch(mutations: readonly SecurityAtomicMutation[], call: Call) {
    if (
      !acknowledged(
        await call.step('EK_SESSION_STORE', (options) =>
          settings.store.atomicBatch(Object.freeze(mutations), options),
        ),
      )
    )
      throw failure();
  }
  async function ownerRows(ownerKey: string, epoch: number, call: Call) {
    const rows = await call.step('EK_SESSION_STORE', (options) =>
      settings.store.listByOwner(records, ownerKey, settings.maxSessions, options),
    );
    try {
      if (
        !Array.isArray(rows) ||
        rows.length > settings.maxSessions ||
        Reflect.ownKeys(rows).length !== rows.length + 1
      )
        throw invalid();
      let bytes = 0;
      const result: State[] = [],
        seen = new Set();
      for (let index = 0; index < rows.length; index++) {
        const field = Object.getOwnPropertyDescriptor(rows, String(index));
        if (!field || !('value' in field)) throw invalid();
        const row = data(field.value, ['id', 'ownerKey', 'version', 'expiresAt', 'fields']);
        id(row.id);
        text(row.version, 256);
        const record = decode(
          {
            ...data(row.fields, [
              'kind',
              'id',
              'ownerKey',
              'identity',
              'subject',
              'policy',
              'epoch',
              'authenticatedAt',
              'assuredAt',
              'createdAt',
              'lastSeenAt',
              'absoluteExpiresAt',
              'expiresAt',
              'digest',
            ]),
            version: row.version,
          },
          row.id,
          settings,
        );
        bytes += Buffer.byteLength(JSON.stringify(record));
        if (
          bytes > 1048576 ||
          seen.has(record.id) ||
          row.ownerKey !== ownerKey ||
          record.ownerKey !== ownerKey ||
          row.expiresAt !== record.expiresAt ||
          (await ownerIndex(record.subject, call)) !== ownerKey
        )
          throw invalid();
        if (record.epoch > epoch) throw failure('EK_SESSION_REVOKED');
        seen.add(record.id);
        if (Date.parse(record.expiresAt) > Date.now()) result.push(record);
      }
      return result;
    } catch {
      call.check();
      throw failure('EK_SESSION_STORE');
    }
  }
  async function prepare(ownerKey: string, epoch: number, call: Call) {
    for (let round = 0; round < 35; round++) {
      const predicate = await guard(ownerKey, call),
        rows = await ownerRows(ownerKey, epoch, call),
        stale = rows.filter((row) => row.epoch < epoch);
      if (!stale.length) return { predicate, active: rows };
      await batch(
        [
          predicate,
          ...stale.slice(0, 31).map((row) => ({
            namespace: records,
            id: row.id,
            ownerKey,
            expectedVersion: row.version,
            next: null,
          })),
        ],
        call,
      );
    }
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
  async function state(
    id: string,
    ownerKey: string,
    auth: SessionAuthentication,
    grant: SessionPolicy,
    epoch: number,
    secret: string,
    call: Call,
    previous?: State,
  ) {
    const now = Date.now(),
      createdAt = previous?.createdAt ?? new Date(now).toISOString(),
      absoluteExpiresAt =
        previous?.absoluteExpiresAt ?? new Date(now + grant.absoluteTtlMs).toISOString();
    if (Date.parse(absoluteExpiresAt) <= now) throw failure('EK_SESSION_EXPIRED');
    const fields = freezeData({
      id,
      ownerKey,
      identity: identityHint(auth.identity),
      subject: hint(auth.subject),
      policy: grant,
      epoch,
      authenticatedAt: auth.authenticatedAt,
      ...(auth.assuredAt ? { assuredAt: auth.assuredAt } : {}),
      createdAt,
      lastSeenAt: new Date(now).toISOString(),
      absoluteExpiresAt,
      expiresAt: new Date(
        Math.min(Date.parse(absoluteExpiresAt), now + grant.idleTtlMs),
      ).toISOString(),
    });
    return freezeData({
      kind: 'session-v1',
      ...fields,
      digest: await digest(domain, macParts(fields, secret), call),
    });
  }
  const issue = (sessionId: string, secret: string, expiresAt: string): SessionIssue =>
    Object.freeze({
      sessionId,
      value: 'ss1.' + sessionId + '.' + secret,
      expiresAt,
      cookieName: '__Host-session',
    });
  const secret = () => {
    const bytes = randomBytes(32);
    try {
      return bytes.toString('base64url');
    } finally {
      bytes.fill(0);
    }
  };
  function parse(token: string) {
    text(token, 4096);
    const match =
      /^ss1\.([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\.([A-Za-z0-9_-]{43})$/.exec(
        token,
      );
    return {
      id: match?.[1] ?? '00000000-0000-4000-8000-000000000000',
      secret: match?.[2] ?? 'invalid',
      valid: !!match,
    };
  }
  async function proven(token: ReturnType<typeof parse>, call: Call) {
    const record = await read(token.id, call);
    if (!dummy) throw failure('EK_RESOURCE_CLOSED');
    const valid = await call.step('EK_SESSION_STORE', (options) =>
      settings.hmac.verify(
        domain,
        record ? macParts(record, token.secret) : ['negative', token.id, token.secret],
        record?.digest ?? dummy!,
        settings.keyRef,
        options,
      ),
    );
    if (typeof valid !== 'boolean') throw failure('EK_SESSION_STORE');
    if (!token.valid || !record || !valid) throw failure();
    if (Date.parse(record.expiresAt) <= Date.now()) throw failure('EK_SESSION_EXPIRED');
    await requireEpoch(record, call);
    return record;
  }
  function operation<T>(
    name: string,
    options: OperationOptions | undefined,
    write: boolean,
    work: (call: Call) => Promise<T>,
  ) {
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
            logger.info('Session operation completed', { operation: name, outcome });
          } catch {
            /* Diagnostics never grant authentication. */
          }
          try {
            telemetry?.addCounter('sessions.' + name + '.completed.' + outcome, 1);
            telemetry?.recordHistogram(
              'sessions.' + name + '.duration',
              performance.now() - started,
            );
          } catch {
            /* Credential data never enters diagnostic failures. */
          }
        }
      })());
    try {
      if (telemetry)
        void Promise.resolve(telemetry.withSpan('sessions.' + name, once)).catch(() => undefined);
    } catch {
      /* Preserve the bounded operation if diagnostics fail. */
    }
    return once();
  }
  const service = Object.freeze<SessionService>({
    async create(input, policyInput, options) {
      const captured = identity(input),
        grant = policy(policyInput, settings.maxSessions, settings.defaultPolicy),
        sessionId = randomUUID();
      return operation('create', options, true, async (call) => {
        const auth = await resolve(captured, 'create', sessionId, call),
          owner = await authorize(
            'sessions.create',
            auth.subject,
            call,
            sessionId,
            grant,
            auth.identity.assurance,
          ),
          ownerKey = await ownerIndex(owner, call);
        await reserve(call, ownerKey, 1000, 'management');
        const epoch = await currentEpoch(ownerKey, call),
          prepared = await prepare(ownerKey, epoch, call);
        if (prepared.active.length >= (grant.maxConcurrentSessions ?? settings.maxSessions))
          throw failure();
        const value = secret(),
          next = await state(sessionId, ownerKey, auth, grant, epoch, value, call);
        await batch(
          [
            prepared.predicate,
            { namespace: records, id: sessionId, ownerKey, expectedVersion: null, next },
          ],
          call,
        );
        await requireEpoch({ ownerKey, epoch }, call);
        return issue(sessionId, value, next.expiresAt);
      });
    },
    async validate(raw, options) {
      const token = parse(raw),
        activity = Date.now();
      return operation('validate', options, true, async (call) => {
        await reserve(call);
        for (let view = 0; view < 2; view++) {
          const previous = await proven(token, call),
            auth = await resolve(previous.identity, 'validate', previous.id, call, previous),
            owner = await authorize(
              'sessions.validate',
              auth.subject,
              call,
              previous.id,
              previous.policy,
              auth.identity.assurance,
            );
          if ((await ownerIndex(owner, call)) !== previous.ownerKey) throw failure();
          let expiry = previous.expiresAt;
          if (Date.parse(previous.lastSeenAt) < activity) {
            const next = await state(
              previous.id,
              previous.ownerKey,
              auth,
              previous.policy,
              previous.epoch,
              token.secret,
              call,
              previous,
            );
            if (
              !acknowledged(
                await call.step('EK_SESSION_STORE', (options) =>
                  settings.store.compareAndSet(
                    records,
                    previous.id,
                    previous.version,
                    next,
                    options,
                  ),
                ),
              )
            ) {
              if (view === 0) {
                await call.step('EK_SESSION_STORE', (options) =>
                  delay(randomInt(1, 4), undefined, options),
                );
                continue;
              }
              throw failure();
            }
            expiry = next.expiresAt;
          } else {
            const fresh = await read(previous.id, call);
            if (!fresh || fresh.version !== previous.version) {
              if (view === 0) continue;
              throw failure('EK_SESSION_REVOKED');
            }
          }
          await requireEpoch(previous, call);
          return freezeData({
            ...auth.identity,
            sessionId: previous.id,
            authenticatedAt: previous.authenticatedAt,
            ...(previous.assuredAt ? { assuredAt: previous.assuredAt } : {}),
            expiresAt: expiry,
          }) satisfies SessionIdentity;
        }
        throw failure();
      });
    },
    async renew(raw, options) {
      const token = parse(raw),
        sessionId = randomUUID();
      return operation('renew', options, true, async (call) => {
        await reserve(call);
        const previous = await proven(token, call),
          auth = await resolve(previous.identity, 'renew', sessionId, call, previous),
          owner = await authorize(
            'sessions.renew',
            auth.subject,
            call,
            previous.id,
            previous.policy,
            auth.identity.assurance,
          ),
          ownerKey = await ownerIndex(owner, call);
        if (ownerKey !== previous.ownerKey) throw failure();
        const predicate = await guard(ownerKey, call),
          value = secret(),
          next = await state(
            sessionId,
            ownerKey,
            auth,
            previous.policy,
            previous.epoch,
            value,
            call,
            previous,
          );
        await batch(
          [
            predicate,
            {
              namespace: records,
              id: previous.id,
              ownerKey,
              expectedVersion: previous.version,
              next: null,
            },
            { namespace: records, id: sessionId, ownerKey, expectedVersion: null, next },
          ],
          call,
        );
        await requireEpoch(previous, call);
        return issue(sessionId, value, next.expiresAt);
      });
    },
    async revoke(sessionId, options) {
      id(sessionId);
      return operation('revoke', options, true, async (call) => {
        const owner = await authorize('sessions.revoke', undefined, call, sessionId),
          ownerKey = await ownerIndex(owner, call);
        await reserve(call, ownerKey, 1000, 'management');
        const predicate = await guard(ownerKey, call),
          previous = await read(sessionId, call);
        if (!previous) return;
        if (previous.ownerKey !== ownerKey || binding(previous.subject) !== binding(owner))
          throw failure();
        await batch(
          [
            predicate,
            {
              namespace: records,
              id: sessionId,
              ownerKey,
              expectedVersion: previous.version,
              next: null,
            },
          ],
          call,
        );
      });
    },
    async revokeAll(input, options) {
      const captured = subject(input);
      return operation('revoke_all', options, true, async (call) => {
        const owner = await authorize('sessions.revoke_all', captured, call),
          ownerKey = await ownerIndex(owner, call);
        await reserve(call, ownerKey, 1000, 'management');
        const epoch = safeEpoch(
          await call.step('EK_SESSION_STORE', (options) =>
            settings.store.bumpOwnerEpoch(epochs, ownerKey, options),
          ),
        );
        if (epoch < 1) throw failure('EK_SESSION_STORE');
        return epoch;
      });
    },
  });
  return {
    service,
    close() {
      dummy = undefined;
      rateOwner = undefined;
      run.close();
    },
    async bootstrap(signal: AbortSignal) {
      await run.run({ signal }, false, async (call) => {
        dummy = await digest(domain, ['negative', randomUUID(), secret()], call);
        rateOwner = createHash('sha256')
          .update(await digest('arkenivajs.sessions.rate-owner.v1', ['verification'], call))
          .digest('hex');
      });
    },
  };
}
