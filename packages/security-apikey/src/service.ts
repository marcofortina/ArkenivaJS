// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes, randomUUID, randomInt } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import type { Logger, OperationOptions, Telemetry } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type {
  ApiKeyIdentity,
  ApiKeyIssue,
  ApiKeyMetadata,
  ApiKeyPolicy,
  ApiKeyService,
  IdentitySubject,
  SecurityAtomicMutation,
} from './contracts.js';
import type { Call, Settings } from './runtime.js';
import { runtime } from './runtime.js';
import {
  binding,
  data,
  failure,
  id,
  instant,
  invalid,
  ip,
  permitted,
  policy,
  subject,
  text,
} from './validation.js';

const records = 'apikey.records.v1',
  guards = 'apikey.owners.v1',
  attempts = 'apikey.attempts.v1',
  domain = 'arkenivajs.apikey.verifier.v1';
interface RecordState {
  readonly id: string;
  readonly ownerKey: string;
  readonly version: string;
  readonly subject: IdentitySubject;
  readonly digest: string;
  readonly policy: ApiKeyPolicy;
  readonly createdAt: string;
  readonly expiresAt: string;
}
const parts = (owner: IdentitySubject) => [
  owner.issuer,
  owner.subject,
  owner.tenant?.tenantId ?? '',
];
const prefix = (keyId: string) => 'ak1.' + keyId;
function acknowledged(input: unknown): boolean {
  try {
    const value = data(input, ['committed', 'version']);
    if (typeof value.committed !== 'boolean') throw invalid();
    if (value.version !== undefined) text(value.version, 256);
    return value.committed;
  } catch {
    throw failure('EK_APIKEY_STORE');
  }
}

function decode(input: unknown, keyId: string): RecordState {
  try {
    const value = data(input, [
      'kind',
      'id',
      'ownerKey',
      'version',
      'subject',
      'digest',
      'policy',
      'createdAt',
      'expiresAt',
    ]);
    if (value.kind !== 'api-key-v1' || value.id !== keyId) throw invalid();
    id(value.id);
    text(value.ownerKey, 64);
    text(value.version, 256);
    text(value.digest, 2048);
    if (!/^[a-f0-9]{64}$/.test(value.ownerKey)) throw invalid();
    const grant = policy(value.policy),
      createdAt = instant(value.createdAt),
      expiresAt = instant(value.expiresAt);
    if (grant.expiresAt !== expiresAt || Date.parse(createdAt) >= Date.parse(expiresAt))
      throw invalid();
    return Object.freeze({
      id: value.id,
      ownerKey: value.ownerKey,
      version: value.version,
      subject: subject(value.subject),
      digest: value.digest,
      policy: grant,
      createdAt,
      expiresAt,
    });
  } catch {
    throw failure('EK_APIKEY_STORE');
  }
}
function metadata(record: RecordState): ApiKeyMetadata {
  return Object.freeze({
    id: record.id,
    keyPrefix: prefix(record.id),
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    scopes: record.policy.scopes,
  });
}
/** Retain only account binding hints; authorization refreshes all runtime tenant provenance. */
function persistedSubject(owner: IdentitySubject): IdentitySubject {
  return freezeData({
    issuer: owner.issuer,
    subject: owner.subject,
    ...(owner.tenant
      ? {
          tenant: {
            tenantId: owner.tenant.tenantId,
            source: owner.tenant.source,
            verifiedAt: owner.tenant.verifiedAt,
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
export function createService(settings: Settings, logger: Logger, telemetry?: Telemetry) {
  const run = runtime(settings);
  let dummy: string | undefined, rateOwner: string | undefined;
  async function digest(label: string, input: readonly string[], call: Call) {
    const result = await call.step('EK_APIKEY_STORE', (options) =>
      settings.hmac.digest(label, Object.freeze([...input]), settings.keyRef, options),
    );
    try {
      text(result, 2048);
      return result;
    } catch {
      throw failure('EK_APIKEY_STORE');
    }
  }
  async function index(label: string, input: readonly string[], call: Call) {
    return createHash('sha256')
      .update(await digest(label, input, call))
      .digest('hex');
  }
  const ownerIndex = (owner: IdentitySubject, call: Call) =>
    index('arkenivajs.apikey.owner.v1', parts(owner), call);
  async function authorized(
    action: string,
    hint: IdentitySubject,
    call: Call,
    grant?: ApiKeyPolicy,
    keyId?: string,
  ) {
    const result = await call.step('EK_APIKEY_INVALID', (options) =>
      settings.require(
        action,
        hint,
        Object.freeze({
          ...(hint.tenant ? { tenant: hint.tenant } : {}),
          ...(grant ? { apiKeyPolicy: grant } : {}),
          ...(keyId ? { apiKeyId: keyId } : {}),
        }),
        options,
      ),
    );
    try {
      const canonical = subject(result);
      if (binding(canonical) !== binding(hint)) throw invalid();
      // Return a snapshot of freshly authorized authority output, never the stored hint.
      return canonical;
    } catch {
      throw failure();
    }
  }
  async function read(keyId: string, call: Call): Promise<RecordState | null> {
    const result = await call.step('EK_APIKEY_STORE', (options) =>
      settings.store.read(records, keyId, options),
    );
    return result === null ? null : decode(result, keyId);
  }
  async function guard(ownerKey: string, call: Call) {
    const result = await call.step('EK_APIKEY_STORE', (options) =>
      settings.store.read(guards, ownerKey, options),
    );
    let expectedVersion: string | null = null;
    if (result !== null) {
      try {
        const value = data(result, ['kind', 'ownerKey', 'version', 'nonce']);
        if (value.kind !== 'api-key-owner-v1' || value.ownerKey !== ownerKey) throw invalid();
        text(value.version, 256);
        id(value.nonce);
        expectedVersion = value.version;
      } catch {
        throw failure('EK_APIKEY_STORE');
      }
    }
    return {
      namespace: guards,
      id: ownerKey,
      ownerKey,
      expectedVersion,
      next: Object.freeze({ kind: 'api-key-owner-v1', ownerKey, nonce: randomUUID() }),
    } satisfies SecurityAtomicMutation;
  }
  async function batch(mutations: readonly SecurityAtomicMutation[], call: Call) {
    const receipt = await call.step('EK_APIKEY_STORE', (options) =>
      settings.store.atomicBatch(Object.freeze(mutations), options),
    );
    if (!acknowledged(receipt)) throw failure();
  }
  async function list(ownerKey: string, call: Call): Promise<readonly RecordState[]> {
    const rows = await call.step('EK_APIKEY_STORE', (options) =>
      settings.store.listByOwner(records, ownerKey, settings.maxKeys, options),
    );
    try {
      if (
        !Array.isArray(rows) ||
        rows.length > settings.maxKeys ||
        Reflect.ownKeys(rows).length !== rows.length + 1
      )
        throw invalid();
      let bytes = 0;
      const seen = new Set<string>(),
        result: RecordState[] = [];
      for (let i = 0; i < rows.length; i++) {
        const entry = Object.getOwnPropertyDescriptor(rows, String(i));
        if (!entry || !('value' in entry)) throw invalid();
        const row = data(entry.value, ['id', 'ownerKey', 'version', 'expiresAt', 'fields']);
        id(row.id);
        text(row.version, 256);
        const fields = data(row.fields, [
          'kind',
          'id',
          'ownerKey',
          'subject',
          'digest',
          'policy',
          'createdAt',
          'expiresAt',
        ]);
        const record = decode({ ...fields, version: row.version }, row.id);
        bytes += Buffer.byteLength(JSON.stringify(record));
        if (
          bytes > 1048576 ||
          seen.has(row.id) ||
          row.ownerKey !== ownerKey ||
          record.ownerKey !== ownerKey ||
          row.expiresAt !== record.expiresAt ||
          (await ownerIndex(record.subject, call)) !== ownerKey
        )
          throw invalid();
        seen.add(row.id);
        if (Date.parse(record.expiresAt) > Date.now()) result.push(record);
      }
      return Object.freeze(result);
    } catch {
      call.check();
      throw failure('EK_APIKEY_STORE');
    }
  }
  async function reserveAttempt(
    call: Call,
    ownerKey = rateOwner,
    maximum = settings.maxAttempts,
    bucket = 'verify',
  ) {
    if (!ownerKey) throw failure('EK_RESOURCE_CLOSED');
    const minute = Math.floor(Date.now() / 60000),
      key = bucket + '-' + ownerKey + ':' + minute;
    // Retry only a definitively rejected counter predicate, never an uncertain write or credential transition.
    for (let count = 0; count < 8; count++) {
      const previous = await call.step('EK_APIKEY_STORE', (options) =>
        settings.store.read(attempts, key, options),
      );
      let expectedVersion: string | null = null,
        total = 0;
      if (previous !== null) {
        try {
          const value = data(previous, [
            'kind',
            'ownerKey',
            'version',
            'minute',
            'count',
            'expiresAt',
          ]);
          text(value.version, 256);
          if (
            value.kind !== 'api-key-attempts-v1' ||
            value.ownerKey !== ownerKey ||
            value.minute !== minute ||
            !Number.isSafeInteger(value.count) ||
            (value.count as number) < 1 ||
            (value.count as number) > maximum ||
            instant(value.expiresAt) !== new Date((minute + 2) * 60000).toISOString()
          )
            throw invalid();
          expectedVersion = value.version;
          total = value.count as number;
        } catch {
          throw failure('EK_APIKEY_STORE');
        }
      }
      if (total >= maximum) throw failure();
      const receipt = await call.step('EK_APIKEY_STORE', (options) =>
        settings.store.compareAndSet(
          attempts,
          key,
          expectedVersion,
          Object.freeze({
            kind: 'api-key-attempts-v1',
            ownerKey,
            minute,
            count: total + 1,
            expiresAt: new Date((minute + 2) * 60000).toISOString(),
          }),
          options,
        ),
      );
      if (acknowledged(receipt)) return;
      if (count < 7)
        await call.step('EK_APIKEY_STORE', (options) => delay(randomInt(1, 4), undefined, options));
    }
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
  async function fresh(owner: IdentitySubject, ownerKey: string, grant: ApiKeyPolicy, call: Call) {
    const keyId = randomUUID(),
      buffer = randomBytes(32);
    let secret: string;
    try {
      secret = buffer.toString('base64url');
    } finally {
      buffer.fill(0);
    }
    const verifier = await digest(domain, [...parts(owner), keyId, secret], call),
      createdAt = new Date().toISOString();
    if (Date.parse(grant.expiresAt) <= Date.now()) throw failure('EK_APIKEY_EXPIRED');
    const next = freezeData({
      kind: 'api-key-v1',
      id: keyId,
      ownerKey,
      subject: persistedSubject(owner),
      digest: verifier,
      policy: grant,
      createdAt,
      expiresAt: grant.expiresAt,
    });
    return {
      mutation: {
        namespace: records,
        id: keyId,
        ownerKey,
        expectedVersion: null,
        next,
      } satisfies SecurityAtomicMutation,
      issue: Object.freeze({
        id: keyId,
        keyPrefix: prefix(keyId),
        value: prefix(keyId) + '.' + secret,
        expiresAt: grant.expiresAt,
      }) satisfies ApiKeyIssue,
    };
  }
  function operation<T>(
    name: 'issue' | 'verify' | 'rotate' | 'revoke' | 'list',
    options: OperationOptions | undefined,
    write: boolean,
    work: (call: Call) => Promise<T>,
  ) {
    const observed = async () => {
      const started = performance.now();
      let status = 'error';
      try {
        const result = await run.run(options, write, work);
        status = 'ok';
        return result;
      } finally {
        try {
          logger.info('API key operation completed', { operation: name, outcome: status });
        } catch {
          /* Diagnostic failure never grants authority or retries a mutation. */
        }
        try {
          telemetry?.addCounter('apikey.' + name + '.completed.' + status, 1);
          telemetry?.recordHistogram('apikey.' + name + '.duration', performance.now() - started);
        } catch {
          /* Credentials never enter the diagnostic error path. */
        }
      }
    };
    // Diagnostic wrappers may neither substitute results nor execute a credential transition twice.
    let execution: Promise<T> | undefined;
    const once = () => (execution ??= observed());
    if (telemetry) {
      try {
        void Promise.resolve(telemetry.withSpan('apikey.' + name, once)).catch(() => undefined);
      } catch {
        /* Execute the same bounded operation without a failed diagnostic wrapper. */
      }
    }
    return once();
  }
  const service: ApiKeyService = Object.freeze<ApiKeyService>({
    async issue(input, grantInput, options) {
      const hint = subject(input),
        grant = policy(grantInput);
      return operation('issue', options, true, async (call) => {
        const owner = await authorized('apikey.issue', hint, call, grant),
          ownerKey = await ownerIndex(owner, call);
        await reserveAttempt(call, ownerKey, 1000, 'management');
        const predicate = await guard(ownerKey, call),
          current = await list(ownerKey, call);
        if (current.length >= settings.maxKeys) throw failure();
        const candidate = await fresh(owner, ownerKey, grant, call);
        await batch([predicate, candidate.mutation], call);
        return candidate.issue;
      });
    },
    async verify(rawKey, context, options) {
      text(rawKey, 4096);
      const captured = data(context, ['clientIp']);
      const clientIp = captured.clientIp === undefined ? undefined : ip(captured.clientIp);
      return operation('verify', options, false, async (call) => {
        await reserveAttempt(call);
        const match =
            /^ak1\.([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\.([A-Za-z0-9_-]{43})$/.exec(
              rawKey,
            ),
          keyId = match?.[1] ?? '00000000-0000-4000-8000-000000000000',
          secret = match?.[2] ?? 'invalid';
        const record = await read(keyId, call);
        if (!dummy) throw failure('EK_RESOURCE_CLOSED');
        const expected = record?.digest ?? dummy,
          inputs = record
            ? [...parts(record.subject), keyId, secret]
            : ['negative', 'negative', '', keyId, secret];
        const verified = await call.step('EK_APIKEY_STORE', (op) =>
          settings.hmac.verify(domain, Object.freeze(inputs), expected, settings.keyRef, op),
        );
        if (typeof verified !== 'boolean') throw failure('EK_APIKEY_STORE');
        if (!match || !record || verified !== true) throw failure();
        if (Date.parse(record.expiresAt) <= Date.now()) throw failure('EK_APIKEY_EXPIRED');
        if (!permitted(clientIp, record.policy.allowedIpRanges)) throw failure();
        const owner = await authorized('apikey.verify', record.subject, call, record.policy, keyId),
          ownerKey = await ownerIndex(owner, call);
        if (ownerKey !== record.ownerKey) throw failure();
        const current = await read(keyId, call);
        if (
          !current ||
          current.version !== record.version ||
          current.digest !== record.digest ||
          Date.parse(current.expiresAt) <= Date.now()
        )
          throw failure('EK_APIKEY_REVOKED');
        return freezeData({
          subject: owner,
          scopes: record.policy.scopes,
          keyId,
        }) satisfies ApiKeyIdentity;
      });
    },
    async rotate(keyId, input, options) {
      id(keyId);
      const hint = subject(input);
      return operation('rotate', options, true, async (call) => {
        const authorizedOwner = await authorized('apikey.rotate', hint, call, undefined, keyId),
          ownerKey = await ownerIndex(authorizedOwner, call);
        await reserveAttempt(call, ownerKey, 1000, 'management');
        const predicate = await guard(ownerKey, call),
          previous = await read(keyId, call);
        if (
          !previous ||
          previous.ownerKey !== ownerKey ||
          binding(previous.subject) !== binding(authorizedOwner)
        )
          throw failure();
        const owner = await authorized(
          'apikey.rotate',
          authorizedOwner,
          call,
          previous.policy,
          keyId,
        );
        if (Date.parse(previous.expiresAt) <= Date.now()) throw failure('EK_APIKEY_EXPIRED');
        const candidate = await fresh(owner, ownerKey, previous.policy, call);
        await batch(
          [
            predicate,
            {
              namespace: records,
              id: keyId,
              ownerKey,
              expectedVersion: previous.version,
              next: null,
            },
            candidate.mutation,
          ],
          call,
        );
        return candidate.issue;
      });
    },
    async revoke(keyId, input, options) {
      id(keyId);
      const hint = subject(input);
      return operation('revoke', options, true, async (call) => {
        const owner = await authorized('apikey.revoke', hint, call, undefined, keyId),
          ownerKey = await ownerIndex(owner, call);
        await reserveAttempt(call, ownerKey, 1000, 'management');
        const predicate = await guard(ownerKey, call),
          previous = await read(keyId, call);
        if (!previous) return;
        if (previous.ownerKey !== ownerKey || binding(previous.subject) !== binding(owner))
          throw failure();
        await batch(
          [
            predicate,
            {
              namespace: records,
              id: keyId,
              ownerKey,
              expectedVersion: previous.version,
              next: null,
            },
          ],
          call,
        );
      });
    },
    async list(input, options) {
      const hint = subject(input);
      return operation('list', options, false, async (call) => {
        const owner = await authorized('apikey.list', hint, call),
          ownerKey = await ownerIndex(owner, call);
        await reserveAttempt(call, ownerKey, 1000, 'management');
        return Object.freeze((await list(ownerKey, call)).map(metadata));
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
        dummy = await digest(
          domain,
          ['negative', 'negative', '', randomUUID(), randomBytes(32).toString('base64url')],
          call,
        );
        rateOwner = await index('arkenivajs.apikey.rate-owner.v1', ['verification'], call);
      });
    },
  };
}
