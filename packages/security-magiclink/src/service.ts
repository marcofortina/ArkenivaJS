// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { OperationOptions } from '@arkenivajs/core';
import type {
  IdentitySubject,
  MagicLinkIdentity,
  MagicLinkIssue,
  MagicLinkIntent,
  MagicLinkService,
  SecurityAtomicMutation,
  MagicLinkAuthorizationContext,
} from './contracts.js';
import type { Settings } from './settings.js';
import { Calls } from './runtime.js';
import type { Observers } from './observation.js';
import type { Call } from './runtime.js';
import { fields, text, intent, issueId, failure } from './validation.js';

const records = 'magiclink.records.v1',
  verifierDomain = 'arkenivajs.magiclink.verifier.v1';
interface Owner {
  readonly issuer: string;
  readonly subject: string;
  readonly tenantId: string;
}
interface RecordState {
  readonly id: string;
  readonly ownerKey: string;
  readonly owner: Owner;
  readonly intent: MagicLinkIntent;
  readonly digest: string;
  readonly validUntil: string;
  readonly expiresAt: string;
  readonly state: 'issued' | 'consumed' | 'revoked';
  readonly version: string;
}
function owner(subject: IdentitySubject): Owner {
  const data = fields(subject, ['issuer', 'subject', 'tenant']);
  const tenant =
    data.tenant === undefined
      ? undefined
      : fields(data.tenant, ['tenantId', 'identity', 'verifiedAt', 'source']);
  return Object.freeze({
    issuer: text(data.issuer, 2048),
    subject: text(data.subject, 512),
    tenantId: tenant ? text(tenant.tenantId, 256) : '',
  });
}
const ownerParts = (value: Owner) => [value.issuer, value.subject, value.tenantId];
const sameOwner = (left: Owner, right: Owner) =>
  left.issuer === right.issuer &&
  left.subject === right.subject &&
  left.tenantId === right.tenantId;
function instant(input: unknown): string {
  const result = text(input, 24);
  if (!Number.isFinite(Date.parse(result)) || new Date(result).toISOString() !== result)
    throw failure('EK_BACKEND_UNAVAILABLE');
  return result;
}
function decode(input: unknown, id: string): RecordState {
  try {
    const value = fields(input, [
      'kind',
      'id',
      'ownerKey',
      'owner',
      'intent',
      'digest',
      'validUntil',
      'expiresAt',
      'state',
      'version',
    ]);
    if (
      value.kind !== 'magic-link-v1' ||
      value.id !== id ||
      !['issued', 'consumed', 'revoked'].includes(value.state as string)
    )
      throw failure();
    const storedOwner = fields(value.owner, ['issuer', 'subject', 'tenantId']),
      ownerKey = text(value.ownerKey, 64),
      validUntil = instant(value.validUntil),
      expiresAt = instant(value.expiresAt);
    if (
      !/^[a-f0-9]{64}$/.test(ownerKey) ||
      Date.parse(expiresAt) <= Date.parse(validUntil) ||
      Date.parse(expiresAt) - Date.parse(validUntil) > 3600000
    )
      throw failure();
    const tenantId = storedOwner.tenantId === '' ? '' : text(storedOwner.tenantId, 256);
    return Object.freeze({
      id: issueId(value.id),
      ownerKey,
      owner: Object.freeze({
        issuer: text(storedOwner.issuer, 2048),
        subject: text(storedOwner.subject, 512),
        tenantId,
      }),
      intent: intent(value.intent),
      digest: text(value.digest, 2048),
      validUntil,
      expiresAt,
      state: value.state as RecordState['state'],
      version: text(value.version, 256),
    });
  } catch {
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
}
function next(
  record: Omit<RecordState, 'version'> | RecordState,
  state = record.state,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    kind: 'magic-link-v1',
    id: record.id,
    ownerKey: record.ownerKey,
    owner: record.owner,
    intent: record.intent,
    digest: record.digest,
    validUntil: record.validUntil,
    expiresAt: record.expiresAt,
    state,
  });
}
function acknowledged(input: unknown): boolean {
  const data = fields(input, ['committed', 'version']);
  if (typeof data.committed !== 'boolean') throw failure('EK_BACKEND_UNAVAILABLE');
  if (data.version !== undefined) text(data.version, 256);
  return data.committed;
}
/** Native random credentials, independently keyed verification and shared atomic state transitions. */
export class Service implements MagicLinkService {
  private readonly calls: Calls;
  private dummy: string | undefined;
  private readonly dummyParts = Object.freeze([
    'negative',
    randomUUID(),
    randomBytes(32).toString('base64url'),
  ]);
  constructor(
    private readonly settings: Settings,
    ownerSignal: AbortSignal,
    ready: () => boolean,
    observers: Observers = {},
  ) {
    this.calls = new Calls(settings, ownerSignal, ready, observers);
  }
  private async digest(domain: string, parts: readonly string[], call: Call): Promise<string> {
    return text(
      await call.step((options) =>
        this.settings.hmac.digest(domain, Object.freeze([...parts]), this.settings.keyRef, options),
      ),
      2048,
    );
  }
  private async index(domain: string, parts: readonly string[], call: Call): Promise<string> {
    return createHash('sha256')
      .update(await this.digest(domain, parts, call))
      .digest('hex');
  }
  private async authorize(
    action: string,
    hint: IdentitySubject | undefined,
    call: Call,
    binding?: MagicLinkAuthorizationContext['magicLink'],
  ): Promise<IdentitySubject> {
    let result: IdentitySubject;
    try {
      result = await this.settings.require(
        action,
        hint,
        {
          ...(hint?.tenant ? { tenant: hint.tenant } : {}),
          ...(binding ? { magicLink: binding } : {}),
        },
        call.options(),
      );
    } catch {
      call.check();
      throw failure();
    }
    call.check();
    owner(result);
    return Object.freeze({
      issuer: result.issuer,
      subject: result.subject,
      ...(result.tenant ? { tenant: result.tenant } : {}),
    });
  }
  private async read(id: string, call: Call): Promise<RecordState | null> {
    const value = await call.step((options) => this.settings.store.read(records, id, options));
    return value === null ? null : decode(value, id);
  }
  private parts(
    record: Omit<RecordState, 'version'> | RecordState,
    secret: string,
  ): readonly string[] {
    return [
      record.id,
      ...ownerParts(record.owner),
      record.ownerKey,
      record.intent,
      record.validUntil,
      secret,
    ];
  }
  private async quota(
    kind: 'issue' | 'consume',
    ownerKey: string,
    call: Call,
  ): Promise<SecurityAtomicMutation> {
    const hour = Math.floor(Date.now() / 3600000),
      namespace = 'magiclink.quota.' + kind + '.v1',
      id = createHash('sha256')
        .update(ownerKey + ':' + hour)
        .digest('hex'),
      current = await call.step((options) => this.settings.store.read(namespace, id, options));
    let count = 0,
      version: string | null = null;
    if (current !== null) {
      const value = fields(current, ['kind', 'ownerKey', 'hour', 'count', 'expiresAt', 'version']);
      if (
        value.kind !== 'magic-link-quota-v1' ||
        value.ownerKey !== ownerKey ||
        value.hour !== hour ||
        !Number.isSafeInteger(value.count) ||
        (value.count as number) < 0 ||
        (value.count as number) > this.settings.maxClaims
      )
        throw failure('EK_BACKEND_UNAVAILABLE');
      count = value.count as number;
      version = text(value.version, 256);
      instant(value.expiresAt);
    }
    if (count >= this.settings.maxClaims) throw failure();
    return Object.freeze({
      namespace,
      id,
      ownerKey,
      expectedVersion: version,
      next: Object.freeze({
        kind: 'magic-link-quota-v1',
        ownerKey,
        hour,
        count: count + 1,
        expiresAt: new Date((hour + 1) * 3600000).toISOString(),
      }),
    });
  }
  async bootstrap(): Promise<void> {
    await this.calls.run(
      undefined,
      async (call) => {
        this.dummy = await this.digest(verifierDomain, this.dummyParts, call);
        if (
          (await call.step((options) =>
            this.settings.hmac.verify(
              verifierDomain,
              this.dummyParts,
              this.dummy!,
              this.settings.keyRef,
              options,
            ),
          )) !== true ||
          (await call.step((options) =>
            this.settings.hmac.verify(
              verifierDomain,
              [...this.dummyParts, 'different'],
              this.dummy!,
              this.settings.keyRef,
              options,
            ),
          )) !== false
        )
          throw failure('EK_BACKEND_UNAVAILABLE');
        await call.step((options) => this.settings.store.read(records, randomUUID(), options));
      },
      true,
    );
  }
  async issue(
    hint: IdentitySubject,
    purpose: MagicLinkIntent,
    options?: OperationOptions,
  ): Promise<MagicLinkIssue> {
    const requested = owner(hint),
      selected = intent(purpose);
    return this.calls.run(
      options,
      async (call) => {
        const authorized = await this.authorize('magiclink.issue.' + selected, hint, call, {
            intent: selected,
            tenantId: requested.tenantId,
          }),
          binding = owner(authorized);
        if (!sameOwner(binding, requested)) throw failure();
        const id = randomUUID(),
          raw = randomBytes(32),
          secret = raw.toString('base64url');
        raw.fill(0);
        const token = 'ml1.' + id + '.' + secret,
          ownerKey = await this.index('arkenivajs.magiclink.owner.v1', ownerParts(binding), call),
          validUntil = new Date(Date.now() + this.settings.ttlMs).toISOString(),
          expiresAt = new Date(Date.parse(validUntil) + 3600000).toISOString();
        const record = {
          id,
          ownerKey,
          owner: binding,
          intent: selected,
          digest: '',
          validUntil,
          expiresAt,
          state: 'issued' as const,
        };
        record.digest = await this.digest(verifierDomain, this.parts(record, secret), call);
        for (let attempt = 0; attempt < 8; attempt++) {
          const quota = await this.quota('issue', ownerKey, call),
            mutation: SecurityAtomicMutation = {
              namespace: records,
              id,
              ownerKey,
              expectedVersion: null,
              next: next(record),
            };
          const committed = acknowledged(
            await call.step(
              (request) => this.settings.store.atomicBatch([quota, mutation], request),
              true,
            ),
          );
          if (!committed) continue;
          if (Date.now() >= Date.parse(validUntil)) throw failure('EK_MAGICLINK_EXPIRED');
          const url = new URL(this.settings.baseUrl);
          url.hash = new URLSearchParams({ token, purpose: selected }).toString();
          return Object.freeze({
            value: token,
            issueId: id,
            expiresAt: validUntil,
            redemptionUrl: url.href,
          });
        }
        throw failure('EK_BACKEND_UNAVAILABLE');
      },
      false,
      { operation: 'issue', purpose: selected },
    );
  }
  async consume(
    token: string,
    context: Readonly<{ method: 'POST'; purpose: MagicLinkIntent }>,
    options?: OperationOptions,
  ): Promise<MagicLinkIdentity> {
    const data = fields(context, ['method', 'purpose']),
      purpose = intent(data.purpose);
    if (data.method !== 'POST') throw failure('EK_CONFIG_INVALID');
    const value = text(token, 84),
      match = /^ml1\.([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/.exec(value);
    if (!match || Buffer.from(match[2]!, 'base64url').toString('base64url') !== match[2])
      throw failure();
    const id = issueId(match[1]),
      secret = match[2]!;
    return this.calls.run(
      options,
      async (call) => {
        for (let attempt = 0; attempt < 8; attempt++) {
          const record = await this.read(id, call);
          const verified = await call.step((request) =>
            this.settings.hmac.verify(
              verifierDomain,
              record ? this.parts(record, secret) : [id, secret, 'absent'],
              record?.digest ?? this.dummy!,
              this.settings.keyRef,
              request,
            ),
          );
          if (verified !== true || !record || record.intent !== purpose) throw failure();
          if (Date.now() >= Date.parse(record.validUntil)) throw failure('EK_MAGICLINK_EXPIRED');
          if (record.state !== 'issued') throw failure('EK_MAGICLINK_REPLAY');
          const authorized = await this.authorize(
            'magiclink.consume.' + purpose,
            { issuer: record.owner.issuer, subject: record.owner.subject },
            call,
            { issueId: id, intent: purpose, tenantId: record.owner.tenantId },
          );
          if (!sameOwner(owner(authorized), record.owner)) throw failure();
          const quota = await this.quota('consume', record.ownerKey, call),
            mutation: SecurityAtomicMutation = {
              namespace: records,
              id,
              ownerKey: record.ownerKey,
              expectedVersion: record.version,
              next: next(record, 'consumed'),
            };
          if (
            !acknowledged(
              await call.step(
                (request) => this.settings.store.atomicBatch([quota, mutation], request),
                true,
              ),
            )
          )
            continue;
          return Object.freeze({
            subject: authorized,
            intent: purpose,
            verifiedAt: new Date().toISOString(),
          });
        }
        throw failure('EK_BACKEND_UNAVAILABLE');
      },
      false,
      { operation: 'consume', purpose },
    );
  }
  async revoke(input: string, options?: OperationOptions): Promise<void> {
    const id = issueId(input);
    await this.calls.run(
      options,
      async (call) => {
        const authorized = await this.authorize('magiclink.revoke', undefined, call, {
            issueId: id,
          }),
          binding = owner(authorized);
        for (let attempt = 0; attempt < 8; attempt++) {
          const record = await this.read(id, call);
          if (!record) return;
          if (!sameOwner(binding, record.owner)) throw failure();
          if (record.state !== 'issued') return;
          if (
            acknowledged(
              await call.step(
                (request) =>
                  this.settings.store.atomicBatch(
                    [
                      {
                        namespace: records,
                        id,
                        ownerKey: record.ownerKey,
                        expectedVersion: record.version,
                        next: next(record, 'revoked'),
                      },
                    ],
                    request,
                  ),
                true,
              ),
            )
          )
            return;
        }
        throw failure('EK_BACKEND_UNAVAILABLE');
      },
      false,
      { operation: 'revoke', purpose: 'none' },
    );
  }
  close(): Promise<void> {
    return this.calls.close();
  }
}
