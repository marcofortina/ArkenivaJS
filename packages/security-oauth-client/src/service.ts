// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes, randomUUID, createHash, randomInt } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import type { Logger, Telemetry, OperationOptions } from '@arkenivajs/core';
import type { CryptoService } from '@arkenivajs/security-crypto';
import { freezeData } from '@arkenivajs/core/support';
import type { OAuthClientService, OAuthGrant, IdentitySubject } from './contracts.js';
import { createBackend } from './backend.js';
import type { NativeTokens, Registration } from './backend.js';
import { createStateCodec, namespaces } from './state.js';
import type { State } from './state.js';
import { runtime } from './runtime.js';
import type { Settings, Call } from './runtime.js';
import { binding, data, failure, id, instant, strings, subject, text } from './validation.js';

const familyEpochs = 'oauth.family-epochs.v1',
  budgets = 'oauth.budgets.v1';
const random = () => {
  const bytes = randomBytes(32);
  try {
    return bytes.toString('base64url');
  } finally {
    bytes.fill(0);
  }
};
const epoch = (input: unknown) => {
  if (!Number.isSafeInteger(input) || (input as number) < 0) throw failure('EK_OAUTH_STATE');
  return input as number;
};
function returnPath(input: unknown): string {
  text(input, 1024);
  if (
    !input.startsWith('/') ||
    input.startsWith('//') ||
    input.includes('\\') ||
    new URL(input, 'https://return.invalid').origin !== 'https://return.invalid'
  )
    throw failure('EK_OAUTH_POLICY');
  return input;
}
function reference(input: unknown, refresh = false) {
  text(input, 4096);
  const uuid = '([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})',
    match = new RegExp(
      refresh
        ? '^or1\\.' + uuid + '\\.' + uuid + '\\.([A-Za-z0-9_-]{43})$'
        : '^os1\\.' + uuid + '\\.([A-Za-z0-9_-]{43})$',
    ).exec(input);
  if (!match) throw failure('EK_OAUTH_STATE');
  return refresh
    ? { id: match[2]!, secret: match[3]!, familyId: match[1]! }
    : { id: match[1]!, secret: match[2]! };
}
/** Outgoing grants remain secrets; neither the SDK response nor a refresh reference grants local identity. */
export function createService(
  settings: Settings,
  crypto: CryptoService,
  logger: Logger,
  telemetry?: Telemetry,
  applicationSignal?: AbortSignal,
  ready: () => boolean = () => true,
) {
  const run = runtime(settings),
    backend = createBackend(settings),
    codec = createStateCodec(settings, crypto),
    registry = new Map(settings.clients.map((client) => [client.id, client])),
    technicalOwner = createHash('sha256')
      .update('arkenivajs.oauth.technical-budget.v1')
      .digest('hex');
  let active = false;
  let closing: Promise<void> | undefined;
  const abort = () => {
    active = false;
    run.abort();
  };
  applicationSignal?.addEventListener('abort', abort, { once: true });
  if (applicationSignal?.aborted) abort();
  const check = () => {
    if (!active || !ready()) throw failure('EK_RESOURCE_CLOSED');
  };
  const request = (audience: unknown, scopes: unknown) => {
    text(audience, 512);
    const allowed = strings(scopes, 64);
    if (!allowed.length) throw failure('EK_OAUTH_POLICY');
    const client = settings.clients.find((item) => item.allowedAudiences.includes(audience));
    if (!client || allowed.some((scope) => !client.allowedScopes.includes(scope)))
      throw failure('EK_OAUTH_POLICY');
    return { client, audience, scopes: allowed };
  };
  const registration = (row: State, revocation = false) => {
    const client = registry.get(row.clientId);
    if (
      !client ||
      client.issuer !== row.issuer ||
      !client.allowedAudiences.includes(row.audience) ||
      (!revocation && row.scopes.some((scope) => !client.allowedScopes.includes(scope)))
    )
      throw failure('EK_OAUTH_POLICY');
    return client;
  };
  async function authorize(
    action: string,
    hint: IdentitySubject | undefined,
    client: Registration,
    audience: string,
    scopes: readonly string[],
    call: Call,
    path?: string,
  ) {
    const result = await call.step('EK_OAUTH_POLICY', (options) =>
      settings.require(
        action,
        hint,
        Object.freeze({
          ...(hint?.tenant ? { tenant: hint.tenant } : {}),
          oauth: Object.freeze({
            clientId: client.id,
            audience,
            scopes,
            ...(path ? { returnPath: path } : {}),
          }),
        }),
        options,
      ),
    );
    try {
      const canonical = subject(result);
      if (hint && binding(canonical) !== binding(hint)) throw failure('EK_OAUTH_POLICY');
      return canonical;
    } catch {
      throw failure('EK_OAUTH_POLICY');
    }
  }
  async function reserve(call: Call) {
    const minute = Math.floor(Date.now() / 60000),
      key = 'grant:' + minute;
    for (let attempt = 0; attempt < 8; attempt++) {
      const before = await call.step('EK_OAUTH_STATE', (options) =>
        settings.store.read(budgets, key, options),
      );
      let count = 0,
        version: string | null = null;
      if (before !== null) {
        const row = data(before, ['kind', 'ownerKey', 'minute', 'count', 'expiresAt', 'version']);
        if (
          row.kind !== 'oauth-budget-v1' ||
          row.ownerKey !== technicalOwner ||
          row.minute !== minute ||
          !Number.isSafeInteger(row.count) ||
          (row.count as number) < 0 ||
          (row.count as number) > 1000 ||
          Date.parse(instant(row.expiresAt)) !== (minute + 2) * 60000
        )
          throw failure('EK_OAUTH_STATE');
        text(row.version, 256);
        version = row.version;
        count = row.count as number;
      }
      if (count >= 1000) throw failure('EK_BACKEND_UNAVAILABLE');
      if (
        codec.receipt(
          await call.step('EK_OAUTH_STATE', (options) =>
            settings.store.compareAndSet(
              budgets,
              key,
              version,
              {
                kind: 'oauth-budget-v1',
                ownerKey: technicalOwner,
                minute,
                count: count + 1,
                expiresAt: new Date((minute + 2) * 60000).toISOString(),
              },
              options,
            ),
          ),
        )
      )
        return;
      await call.step('EK_OAUTH_STATE', (options) => delay(randomInt(1, 4), undefined, options));
    }
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
  async function current(row: Pick<State, 'owner' | 'macRef' | 'familyId' | 'epoch'>, call: Call) {
    const key = await codec.familyKey(row, call),
      value = epoch(
        await call.step('EK_OAUTH_STATE', (options) =>
          settings.store.currentOwnerEpoch(familyEpochs, key, options),
        ),
      );
    if (value !== row.epoch) throw failure('EK_OAUTH_STATE');
    return key;
  }
  async function proven(
    raw: ReturnType<typeof reference>,
    kind: 'authorization' | 'refresh',
    call: Call,
  ) {
    const row = await codec.read(kind, raw.id, call);
    if (!row) {
      const input = Buffer.from('arkenivajs.oauth.negative.v1:' + raw.id),
        empty = Buffer.alloc(32);
      try {
        await call.step('EK_OAUTH_STATE', () =>
          crypto.verifyMac(input, empty, settings.macRefs[0]!, { signal: call.options().signal! }),
        );
      } finally {
        input.fill(0);
        empty.fill(0);
      }
      throw failure('EK_OAUTH_STATE');
    }
    if (
      (kind === 'refresh' && (!('familyId' in raw) || row.familyId !== raw.familyId)) ||
      !(await codec.prove(row, raw.secret, call)) ||
      Date.parse(row.expiresAt) <= Date.now()
    )
      throw failure('EK_OAUTH_STATE');
    return row;
  }
  async function claim(row: State, secret: string, call: Call) {
    const next = await codec.spend(row, secret, call);
    if (
      !codec.receipt(
        await call.step('EK_OAUTH_STATE', (options) =>
          settings.store.compareAndSet(namespaces[row.kind], row.id, row.version, next, options),
        ),
      )
    )
      throw failure('EK_OAUTH_STATE');
  }
  function grant(
    tokens: NativeTokens,
    requested: readonly string[],
    client: Registration,
    audience: string,
  ) {
    const access = tokens.access_token;
    text(access, 16384);
    if (
      typeof tokens.token_type !== 'string' ||
      tokens.token_type.toLowerCase() !== 'bearer' ||
      !Number.isSafeInteger(tokens.expires_in) ||
      tokens.expires_in! <= 0 ||
      tokens.expires_in! > 86400
    )
      throw failure('EK_OAUTH_PROVIDER');
    const scopes =
      tokens.scope === undefined
        ? requested
        : strings(typeof tokens.scope === 'string' ? tokens.scope.split(' ') : undefined, 64);
    if (
      !scopes.length ||
      scopes.some((scope) => !requested.includes(scope) || !client.allowedScopes.includes(scope))
    )
      throw failure('EK_OAUTH_POLICY');
    if (tokens.refresh_token !== undefined) text(tokens.refresh_token, 8192);
    return {
      accessToken: access,
      tokenType: 'Bearer' as const,
      expiresAt: new Date(Date.now() + tokens.expires_in! * 1000).toISOString(),
      scopes,
      audience,
    };
  }
  async function head(row: State, call: Call) {
    const family = await codec.read('family', row.familyId!, call);
    if (
      !family ||
      !(await codec.prove(family, '', call)) ||
      binding(family.owner) !== binding(row.owner) ||
      family.familyId !== row.familyId ||
      family.clientId !== row.clientId ||
      family.issuer !== row.issuer ||
      family.audience !== row.audience ||
      family.epoch !== row.epoch
    )
      throw failure('EK_OAUTH_STATE');
    const payload = data(await codec.open(family, call), ['currentId']);
    id(payload.currentId);
    return { family, currentId: payload.currentId };
  }
  async function persist(
    tokens: NativeTokens,
    client: Registration,
    owner: IdentitySubject,
    audience: string,
    scopes: readonly string[],
    call: Call,
    previous?: State,
    expectedHead?: State,
  ): Promise<OAuthGrant> {
    const result = grant(tokens, scopes, client, audience);
    if (tokens.refresh_token === undefined) return freezeData(result);
    const familyId = previous?.familyId ?? randomUUID(),
      refId = randomUUID(),
      secret = random(),
      macRef = previous?.macRef ?? settings.macRefs[0]!,
      expiresAt = previous?.expiresAt ?? new Date(Date.now() + settings.refreshTtlMs).toISOString(),
      key = await codec.familyKey({ owner, macRef, familyId }, call),
      generation =
        previous?.epoch ??
        epoch(
          await call.step('EK_OAUTH_STATE', (options) =>
            settings.store.currentOwnerEpoch(familyEpochs, key, options),
          ),
        ),
      common = {
        owner,
        clientId: client.id,
        issuer: client.issuer,
        audience,
        scopes: result.scopes,
        expiresAt,
        encRef: settings.encryptionRefs[0]!,
        macRef,
        familyId,
        epoch: generation,
        status: 'active' as const,
      },
      next = await codec.make(
        { ...common, kind: 'refresh', id: refId },
        { refreshToken: tokens.refresh_token },
        secret,
        call,
      ),
      family = await codec.make(
        { ...common, kind: 'family', id: familyId },
        { currentId: refId },
        '',
        call,
      );
    if (
      !codec.receipt(
        await call.step('EK_OAUTH_STATE', (options) =>
          settings.store.atomicBatch(
            [
              {
                namespace: namespaces.refresh,
                id: refId,
                ownerKey: next.ownerKey,
                expectedVersion: null,
                next,
              },
              {
                namespace: namespaces.family,
                id: familyId,
                ownerKey: family.ownerKey,
                expectedVersion: expectedHead?.version ?? null,
                next: family,
              },
            ],
            options,
          ),
        ),
      )
    )
      throw failure('EK_OAUTH_STATE');
    await current({ ...common }, call);
    return freezeData({ ...result, refreshRef: 'or1.' + familyId + '.' + refId + '.' + secret });
  }
  async function revokeFamily(row: State, client: Registration, call: Call, explicit = false) {
    const key = await codec.familyKey(row, call),
      generation = epoch(
        await call.step('EK_OAUTH_STATE', (options) =>
          settings.store.currentOwnerEpoch(familyEpochs, key, options),
        ),
      );
    if (generation === row.epoch)
      epoch(
        await call.step('EK_OAUTH_STATE', (options) =>
          settings.store.bumpOwnerEpoch(familyEpochs, key, options),
        ),
      );
    else if (!explicit) return;
    const latest = await head(row, call),
      record = await codec.read('refresh', latest.currentId, call);
    if (
      !record ||
      record.familyId !== row.familyId ||
      binding(record.owner) !== binding(row.owner) ||
      record.clientId !== row.clientId
    )
      throw failure('EK_OAUTH_STATE');
    const payload = data(await codec.open(record, call), ['refreshToken']);
    text(payload.refreshToken, 8192);
    await backend.revoke(client, payload.refreshToken, call);
  }
  function operation<T>(
    name: string,
    options: OperationOptions | undefined,
    work: (call: Call) => Promise<T>,
  ) {
    check();
    let execution: Promise<T> | undefined;
    const once = () =>
      (execution ??= (async () => {
        const started = performance.now();
        let outcome = 'error';
        try {
          const result = await run.run(options, true, async (call) => {
            await reserve(call);
            return work(call);
          });
          outcome = 'ok';
          return result;
        } finally {
          try {
            logger.info('OAuth operation completed', { operation: name, outcome });
          } catch {
            /* Grant data never enters diagnostics. */
          }
          try {
            telemetry?.addCounter('oauth.' + name + '.completed.' + outcome, 1);
            telemetry?.recordHistogram('oauth.' + name + '.duration', performance.now() - started);
          } catch {
            /* Observers cannot substitute or repeat a grant. */
          }
        }
      })());
    try {
      if (telemetry)
        void Promise.resolve(telemetry.withSpan('oauth.' + name, once)).catch(() => undefined);
    } catch {
      /* Preserve the bounded operation. */
    }
    return once();
  }
  const service = Object.freeze<OAuthClientService>({
    async beginAuthorization(input, options) {
      const value = data(input, ['subject', 'audience', 'scopes', 'returnPath']),
        hint = value.subject === undefined ? undefined : subject(value.subject),
        path = returnPath(value.returnPath),
        requested = request(value.audience, value.scopes);
      return operation('begin_authorization', options, async (call) => {
        const owner = await authorize(
            'oauth.begin_authorization',
            hint,
            requested.client,
            requested.audience,
            requested.scopes,
            call,
            path,
          ),
          key = randomUUID(),
          secret = random(),
          stateRef = 'os1.' + key + '.' + secret,
          nonce = random(),
          verifier = random(),
          expiresAt = new Date(Date.now() + settings.stateTtlMs).toISOString(),
          authorizationUrl = await backend.authorization(
            requested.client,
            requested.scopes,
            stateRef,
            nonce,
            verifier,
            requested.audience,
            call,
          ),
          record = await codec.make(
            {
              kind: 'authorization',
              id: key,
              status: 'active',
              owner,
              clientId: requested.client.id,
              issuer: requested.client.issuer,
              audience: requested.audience,
              scopes: requested.scopes,
              expiresAt,
              encRef: settings.encryptionRefs[0]!,
              macRef: settings.macRefs[0]!,
            },
            { nonce, verifier, redirectUri: requested.client.redirectUri, returnPath: path },
            secret,
            call,
          );
        if (
          !codec.receipt(
            await call.step('EK_OAUTH_STATE', (opts) =>
              settings.store.compareAndSet(namespaces.authorization, key, null, record, opts),
            ),
          )
        )
          throw failure('EK_OAUTH_STATE');
        return Object.freeze({ authorizationUrl, stateRef, expiresAt });
      });
    },
    async exchangeCode(input, options) {
      const value = data(input, ['stateRef', 'code', 'issuer', 'redirectUri']),
        raw = reference(value.stateRef);
      text(value.code, 4096);
      text(value.issuer, 2048);
      text(value.redirectUri, 2048);
      return operation('exchange_code', options, async (call) => {
        const row = await proven(raw, 'authorization', call),
          client = registration(row);
        if (
          row.status !== 'active' ||
          value.issuer !== client.issuer ||
          value.redirectUri !== client.redirectUri
        )
          throw failure('EK_OAUTH_STATE');
        const payload = data(await codec.open(row, call), [
          'nonce',
          'verifier',
          'redirectUri',
          'returnPath',
        ]);
        text(payload.nonce, 128);
        text(payload.verifier, 128);
        if (payload.redirectUri !== client.redirectUri) throw failure('EK_OAUTH_STATE');
        const path = returnPath(payload.returnPath),
          owner = await authorize(
            'oauth.exchange_code',
            row.owner,
            client,
            row.audience,
            row.scopes,
            call,
            path,
          );
        await claim(row, raw.secret, call);
        const tokens = await backend.exchange(
          client,
          value.code as string,
          value.stateRef as string,
          payload.nonce,
          payload.verifier,
          row.scopes,
          row.audience,
          call,
        );
        return persist(tokens, client, owner, row.audience, row.scopes, call);
      });
    },
    async clientCredentials(audience, scopes, options) {
      const requested = request(audience, scopes);
      return operation('client_credentials', options, async (call) => {
        const owner = await authorize(
            'oauth.client_credentials',
            undefined,
            requested.client,
            requested.audience,
            requested.scopes,
            call,
          ),
          tokens = await backend.credentials(
            requested.client,
            requested.scopes,
            requested.audience,
            call,
          );
        return persist(tokens, requested.client, owner, requested.audience, requested.scopes, call);
      });
    },
    async refresh(input, options) {
      const raw = reference(input, true);
      return operation('refresh', options, async (call) => {
        const row = await proven(raw, 'refresh', call),
          client = registration(row),
          owner = await authorize(
            'oauth.refresh',
            row.owner,
            client,
            row.audience,
            row.scopes,
            call,
          );
        if (row.status === 'spent') {
          await revokeFamily(row, client, call);
          throw failure('EK_OAUTH_STATE');
        }
        await current(row, call);
        const latest = await head(row, call);
        if (latest.currentId !== row.id) throw failure('EK_OAUTH_STATE');
        const payload = data(await codec.open(row, call), ['refreshToken']);
        text(payload.refreshToken, 8192);
        await claim(row, raw.secret, call);
        let tokens: NativeTokens;
        try {
          tokens = await backend.refresh(
            client,
            payload.refreshToken,
            row.scopes,
            row.audience,
            call,
          );
        } catch (error) {
          try {
            await revokeFamily(row, client, call);
          } catch {
            /* Keep an uncertain upstream outcome closed. */
          }
          throw error;
        }
        if (
          typeof tokens.refresh_token !== 'string' ||
          tokens.refresh_token === payload.refreshToken
        ) {
          await revokeFamily(row, client, call);
          throw failure('EK_OAUTH_POLICY');
        }
        return persist(tokens, client, owner, row.audience, row.scopes, call, row, latest.family);
      });
    },
    async revoke(input, options) {
      const raw = reference(input, true);
      return operation('revoke', options, async (call) => {
        const row = await proven(raw, 'refresh', call),
          client = registration(row, true);
        await authorize('oauth.revoke', row.owner, client, row.audience, row.scopes, call);
        await revokeFamily(row, client, call, true);
      });
    },
  });
  return {
    service,
    async bootstrap(signal: AbortSignal) {
      await run.run({ signal }, false, (call) => backend.bootstrap(call));
      active = true;
    },
    close(options?: OperationOptions) {
      return (closing ??= (async () => {
        abort();
        applicationSignal?.removeEventListener('abort', abort);
        await run.close();
        await backend.close(options);
      })());
    },
  };
}
