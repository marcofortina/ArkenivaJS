// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes, randomInt, timingSafeEqual, X509Certificate } from 'node:crypto';
import { TextDecoder, types } from 'node:util';
import { performance } from 'node:perf_hooks';
import type { OperationOptions } from '@arkenivajs/core';
import { freezeData, instrumentOperation } from '@arkenivajs/core/support';
import { recorder } from './observation.js';
import type { Observers, Operation } from './observation.js';
import type { SamlService, SamlLoginRequest, SamlVerifiedIdentity } from './contracts.js';
import type {
  NativeConfiguration,
  NativeRequest,
  NativeResult,
  VerifiedAssertion,
  LogoutProfile,
} from './backend-contracts.js';
import type { Settings } from './settings.js';
import { Runtime } from './runtime.js';
import type { Call } from './runtime.js';
import { credentials } from './credentials.js';
import { native } from './backend.js';
import { fields, failure, text, requestId, returnPath, list } from './validation.js';
import { parse } from './xml.js';

const digest = (value: unknown): string => {
  const ordered = (input: unknown): unknown =>
    Array.isArray(input)
      ? input.map(ordered)
      : input && typeof input === 'object'
        ? Object.fromEntries(
            Object.keys(input)
              .sort()
              .map((key) => [key, ordered((input as Record<string, unknown>)[key])]),
          )
        : input;
  return createHash('sha256')
    .update(JSON.stringify(ordered(value)))
    .digest('hex');
};
const nextId = () => '_' + randomBytes(20).toString('hex');
const instant = (value: unknown): string => {
  if (
    typeof value !== 'string' ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  )
    throw failure('EK_SAML_REPLAY');
  return value;
};
interface RequestRecord {
  readonly kind: 'login' | 'logout';
  readonly id: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly binding: 'redirect' | 'post';
  readonly returnPath: string;
}
export function managed(
  settings: Settings,
  owner?: AbortSignal,
  ready?: () => boolean,
  observers: Observers = {},
) {
  const record = recorder(observers),
    runtime = new Runtime(ready, owner, record.capacity),
    namespace = 'saml:' + settings.profile;
  async function operation<T>(
    name: Operation,
    options: OperationOptions | undefined,
    work: (call: Call) => Promise<T>,
    bootstrap = false,
  ): Promise<T> {
    const started = performance.now();
    let failure: unknown;
    try {
      return await instrumentOperation(
        observers.telemetry,
        'saml.operation',
        { 'saml.operation': name },
        () => runtime.run(options, work, bootstrap),
        () => {},
      );
    } catch (error) {
      failure = error;
      throw error;
    } finally {
      record.complete(name, performance.now() - started, failure);
    }
  }
  async function read(call: Call, kind: 'login' | 'logout', id: string): Promise<RequestRecord> {
    const raw = await call.step('EK_BACKEND_UNAVAILABLE', (options) =>
      settings.store.read(namespace + ':requests', 'r' + id, options),
    );
    if (!raw) throw failure('EK_SAML_REPLAY');
    const row = fields(raw, [
      'kind',
      'ownerKey',
      'id',
      'createdAt',
      'expiresAt',
      'binding',
      'returnPath',
      'version',
    ]);
    if (
      row.kind !== kind ||
      row.ownerKey !== settings.profile ||
      row.id !== id ||
      row.binding !== settings.binding
    )
      throw failure('EK_SAML_REPLAY');
    const createdAt = instant(row.createdAt),
      expiresAt = instant(row.expiresAt);
    if (
      Date.parse(expiresAt) !== Date.parse(createdAt) + 300000 ||
      Date.now() >= Date.parse(expiresAt) ||
      Date.parse(createdAt) > Date.now() + 1000
    )
      throw failure('EK_SAML_REPLAY');
    return Object.freeze({
      kind,
      id,
      createdAt,
      expiresAt,
      binding: settings.binding,
      returnPath: returnPath(row.returnPath),
    });
  }
  async function reserve(call: Call): Promise<void> {
    const minute = Math.floor(Date.now() / 60000),
      expiresAt = new Date((minute + 2) * 60000).toISOString();
    for (let attempt = 0; attempt < 8; attempt++) {
      const accepted = await call.mutate((options) =>
        settings.store.claimOnce(
          namespace + ':capacity',
          digest(['capacity', minute, randomInt(1000)]),
          expiresAt,
          options,
        ),
      );
      if (accepted === true) return;
      if (accepted !== false) throw failure('EK_BACKEND_UNAVAILABLE');
    }
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
  async function backend(
    call: Call,
    action: NativeRequest['action'],
    id: string,
    createdAt: string,
    response?: string,
    profile?: LogoutProfile,
  ): Promise<NativeResult> {
    if (settings.trusted.expiresAt !== undefined && settings.trusted.expiresAt <= Date.now())
      throw failure('EK_SAML_CONFIGURATION');
    const keys = await credentials(settings, call);
    const certificates = settings.trusted.certificates.filter((pem) => {
      const certificate = new X509Certificate(pem);
      return (
        Date.now() >= Date.parse(certificate.validFrom) &&
        Date.now() < Date.parse(certificate.validTo)
      );
    });
    if (!certificates.length) throw failure('EK_SAML_CONFIGURATION');
    const configuration: NativeConfiguration = {
      entityId: settings.entityId,
      acsUrl: settings.acsUrl,
      audience: settings.audience,
      issuer: settings.trusted.issuer,
      certificates,
      loginUrl: settings.trusted.loginUrl,
      ...(settings.trusted.logoutUrl ? { logoutUrl: settings.trusted.logoutUrl } : {}),
      clockSkewSeconds: settings.clockSkewSeconds,
      binding: settings.binding,
      ...(settings.authenticationRequestProfile
        ? { authenticationRequestProfile: settings.authenticationRequestProfile }
        : {}),
      ...(settings.requestedAuthnContext
        ? { requestedAuthnContext: settings.requestedAuthnContext }
        : {}),
      ...keys,
    };
    return call.step('EK_SAML_ASSERTION', (options) =>
      native(
        {
          action,
          configuration,
          requestId: id,
          instant: createdAt,
          relayState: id,
          ...(response === undefined ? {} : { response }),
          ...(profile === undefined ? {} : { profile }),
        },
        options.signal,
      ),
    );
  }
  async function save(call: Call, record: RequestRecord): Promise<void> {
    const result = fields(
      await call.mutate((options) =>
        settings.store.compareAndSet(
          namespace + ':requests',
          'r' + record.id,
          null,
          { ...record, ownerKey: settings.profile },
          options,
        ),
      ),
      ['committed', 'version'],
    );
    if (result.committed !== true) throw failure('EK_SAML_REPLAY');
  }
  async function consume(
    call: Call,
    record: RequestRecord,
    responseId: string,
    assertionId?: string,
  ): Promise<void> {
    if (Date.now() >= Date.parse(record.expiresAt)) throw failure('EK_SAML_REPLAY');
    const replayExpiresAt = new Date(
      Date.now() + 300000 + settings.clockSkewSeconds * 2000,
    ).toISOString();
    for (const [kind, id] of [
      ['request', record.id],
      ['response', responseId],
      ...(assertionId === undefined ? [] : [['assertion', assertionId]]),
    ]) {
      const accepted = await call.mutate((options) =>
        settings.store.claimOnce(namespace + ':used', digest([kind, id]), replayExpiresAt, options),
      );
      if (accepted !== true) throw failure('EK_SAML_REPLAY');
    }
  }
  async function transfer(
    call: Call,
    kind: 'login' | 'logout',
    path: string,
    profile?: LogoutProfile,
  ): Promise<SamlLoginRequest> {
    await reserve(call);
    const id = nextId(),
      result = await backend(call, kind, id, new Date().toISOString(), undefined, profile);
    if (result.kind !== 'redirect' && result.kind !== 'post') throw failure('EK_SAML_ASSERTION');
    const createdAt = instant(result.createdAt),
      expiresAt = new Date(Date.parse(createdAt) + 300000).toISOString();
    const endpoint = kind === 'login' ? settings.trusted.loginUrl : settings.trusted.logoutUrl!;
    let request: SamlLoginRequest;
    if (result.kind === 'redirect') {
      const target = new URL(text(result.url, 524288)),
        expected = new URL(endpoint);
      if (
        target.origin !== expected.origin ||
        target.pathname !== expected.pathname ||
        target.hash ||
        target.searchParams.get('RelayState') !== id ||
        !target.searchParams.get('SAMLRequest')
      )
        throw failure('EK_SAML_ASSERTION');
      request = { binding: 'redirect', requestId: id, redirectUrl: result.url, expiresAt };
    } else {
      const value = fields(result.fields, ['SAMLRequest', 'RelayState']);
      if (value.RelayState !== id) throw failure('EK_SAML_ASSERTION');
      request = {
        binding: 'post',
        requestId: id,
        actionUrl: endpoint,
        fields: { SAMLRequest: text(value.SAMLRequest, 524288), RelayState: id },
        expiresAt,
      };
    }
    await save(call, {
      kind,
      id,
      createdAt,
      expiresAt,
      binding: settings.binding,
      returnPath: path,
    });
    return freezeData(request);
  }
  function identity(input: VerifiedAssertion, id: string): SamlVerifiedIdentity {
    if (input.issuer !== settings.trusted.issuer) throw failure('EK_SAML_ASSERTION');
    return freezeData({
      issuer: settings.trusted.issuer,
      subject: text(input.subject, 1024),
      audience: [settings.audience],
      scopes: [],
      assurance: 'single-factor' as const,
      claims: {
        saml: {
          transactionId: id,
          nameIDFormat: input.nameIDFormat,
          ...(input.authnContext ? { authnContext: input.authnContext } : {}),
          ...(input.nameQualifier ? { nameQualifier: input.nameQualifier } : {}),
          ...(input.spNameQualifier ? { spNameQualifier: input.spNameQualifier } : {}),
        },
      },
      attributes: input.attributes,
      ...(input.sessionIndex === undefined ? {} : { sessionIndex: input.sessionIndex }),
    });
  }
  function snapshot(input: SamlVerifiedIdentity): SamlVerifiedIdentity {
    const value = fields(input, [
      'issuer',
      'subject',
      'audience',
      'scopes',
      'assurance',
      'claims',
      'attributes',
      'sessionIndex',
    ]);
    const audience = list(value.audience, 1),
      scopes = list(value.scopes, 0);
    if (
      value.issuer !== settings.trusted.issuer ||
      value.assurance !== 'single-factor' ||
      audience.length !== 1 ||
      audience[0] !== settings.audience ||
      scopes.length !== 0
    )
      throw failure('EK_SAML_ASSERTION');
    const claims = fields(value.claims, ['saml']),
      saml = fields(claims.saml, [
        'transactionId',
        'authnContext',
        'nameIDFormat',
        'nameQualifier',
        'spNameQualifier',
      ]);
    requestId(saml.transactionId);
    text(saml.nameIDFormat, 2048);
    if (saml.authnContext !== undefined) text(saml.authnContext, 2048);
    if (saml.nameQualifier !== undefined) text(saml.nameQualifier, 2048);
    if (saml.spNameQualifier !== undefined) text(saml.spNameQualifier, 2048);
    text(value.subject, 1024);
    if (value.sessionIndex !== undefined) text(value.sessionIndex, 256);
    const rawAttributes = value.attributes;
    if (!rawAttributes || typeof rawAttributes !== 'object' || types.isProxy(rawAttributes))
      throw failure('EK_SAML_ASSERTION');
    const names = Reflect.ownKeys(rawAttributes);
    if (names.length > 128 || names.some((key) => typeof key !== 'string'))
      throw failure('EK_SAML_ASSERTION');
    const selected = fields(rawAttributes, names as string[], 128),
      attributes: Record<string, readonly string[]> = Object.create(null);
    let bytes = 0;
    for (const [name, values] of Object.entries(selected)) {
      text(name, 256);
      attributes[name] = list(values, 32).map((value) => text(value, 8192));
      bytes +=
        Buffer.byteLength(name) +
        attributes[name]!.reduce((sum, value) => sum + Buffer.byteLength(value), 0);
      if (bytes > 32768) throw failure('EK_SAML_ASSERTION');
    }
    return freezeData({
      ...value,
      audience,
      scopes,
      attributes,
      claims: { saml },
    }) as unknown as SamlVerifiedIdentity;
  }
  const service: SamlService = Object.freeze<SamlService>({
    async beginLogin(context, options) {
      const value = fields(context, ['returnPath']),
        path = returnPath(value.returnPath);
      return operation('begin_login', options, (call) => transfer(call, 'login', path));
    },
    async consumeResponse(context, response, options) {
      const value = fields(context, ['inResponseTo', 'relayState']),
        id = requestId(value.inResponseTo);
      if (
        value.relayState !== id ||
        typeof response !== 'string' ||
        !response ||
        response.length > 349528
      )
        throw failure('EK_SAML_ASSERTION');
      return operation('consume_response', options, async (call) => {
        const record = await read(call, 'login', id);
        await reserve(call);
        const result = await backend(call, 'verify-login', id, record.createdAt, response);
        if (result.kind !== 'identity') throw failure('EK_SAML_ASSERTION');
        const verified = identity(result.identity, id);
        await consume(call, record, result.identity.responseId, result.identity.assertionId);
        const receipt = fields(
          await call.mutate((options) =>
            settings.store.compareAndSet(
              namespace + ':sessions',
              'r' + id,
              null,
              {
                ownerKey: settings.profile,
                identityDigest: digest(verified),
                expiresAt: result.identity.sessionExpiresAt,
              },
              options,
            ),
          ),
          ['committed', 'version'],
        );
        if (receipt.committed !== true) throw failure('EK_SAML_REPLAY');
        return verified;
      });
    },
    async createMetadata() {
      return operation('metadata', undefined, async (call) => {
        const result = await backend(call, 'metadata', nextId(), new Date().toISOString());
        if (result.kind !== 'metadata' || Buffer.byteLength(result.xml) > 524288)
          throw failure('EK_SAML_CONFIGURATION');
        return result.xml;
      });
    },
    async beginLogout(input, options) {
      const value = snapshot(input);
      return operation('begin_logout', options, async (call) => {
        if (!settings.authority || !settings.signingKeyRef || !settings.trusted.logoutUrl)
          throw failure('EK_SAML_CONFIGURATION');
        const approved = fields(
          await call.step('EK_SAML_ASSERTION', (options) =>
            settings.authority!.require(
              'saml.logout',
              { issuer: value.issuer, subject: value.subject },
              {},
              options,
            ),
          ),
          ['issuer', 'subject', 'tenant'],
        );
        if (approved.issuer !== value.issuer || approved.subject !== value.subject)
          throw failure('EK_SAML_ASSERTION');
        const claim = value.claims.saml as Readonly<Record<string, unknown>>,
          id = requestId(claim.transactionId);
        const stored = await call.step('EK_BACKEND_UNAVAILABLE', (options) =>
          settings.store.read(namespace + ':sessions', 'r' + id, options),
        );
        if (!stored) throw failure('EK_SAML_ASSERTION');
        const session = fields(stored, ['ownerKey', 'identityDigest', 'expiresAt', 'version']);
        const expected = Buffer.from(text(session.identityDigest, 64)),
          actual = Buffer.from(digest(value));
        if (
          session.ownerKey !== settings.profile ||
          Date.parse(instant(session.expiresAt)) <= Date.now() ||
          expected.length !== actual.length ||
          !timingSafeEqual(expected, actual)
        )
          throw failure('EK_SAML_ASSERTION');
        return transfer(call, 'logout', '/', {
          nameID: value.subject,
          nameIDFormat: text(claim.nameIDFormat, 2048),
          ...(value.sessionIndex === undefined ? {} : { sessionIndex: value.sessionIndex }),
          ...(claim.nameQualifier === undefined
            ? {}
            : { nameQualifier: text(claim.nameQualifier, 2048) }),
          ...(claim.spNameQualifier === undefined
            ? {}
            : { spNameQualifier: text(claim.spNameQualifier, 2048) }),
        });
      });
    },
    async consumeLogoutResponse(input, options) {
      if (typeof input !== 'string' || !input || input.length > 524288)
        throw failure('EK_SAML_ASSERTION');
      return operation('consume_logout_response', options, async (call) => {
        let response = input,
          relayState: string | undefined;
        if (
          settings.binding === 'post' &&
          (input.startsWith('SAMLResponse=') || input.startsWith('RelayState='))
        ) {
          const form = new URLSearchParams(input);
          if (
            [...form.keys()].some((name) => !['SAMLResponse', 'RelayState'].includes(name)) ||
            form.getAll('SAMLResponse').length !== 1 ||
            form.getAll('RelayState').length > 1
          )
            throw failure('EK_SAML_ASSERTION');
          response = form.get('SAMLResponse')!;
          relayState = form.get('RelayState') ?? undefined;
        }
        let xml: string;
        if (settings.binding === 'post')
          xml = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(response, 'base64'));
        else {
          const { inflateRawSync } = await import('node:zlib');
          const form = new URLSearchParams(response.startsWith('?') ? response.slice(1) : response),
            encoded = form.get('SAMLResponse');
          if (!encoded || form.getAll('SAMLResponse').length !== 1)
            throw failure('EK_SAML_ASSERTION');
          xml = new TextDecoder('utf-8', { fatal: true }).decode(
            inflateRawSync(Buffer.from(encoded, 'base64'), { maxOutputLength: 262144 }),
          );
        }
        const root = parse(xml).documentElement,
          id = requestId(root.getAttribute('InResponseTo'));
        if (relayState !== undefined && relayState !== id) throw failure('EK_SAML_ASSERTION');
        const record = await read(call, 'logout', id);
        await reserve(call);
        const result = await backend(call, 'verify-logout', id, record.createdAt, response);
        if (result.kind !== 'logout') throw failure('EK_SAML_ASSERTION');
        await consume(call, record, result.responseId);
      });
    },
  });
  return {
    service,
    close: () => runtime.close(),
    drain: () => runtime.drain(),
    async bootstrap() {
      await operation(
        'bootstrap',
        undefined,
        async (call) => {
          await credentials(settings, call);
        },
        true,
      );
    },
  };
}
