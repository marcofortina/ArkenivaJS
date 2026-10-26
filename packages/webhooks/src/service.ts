// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes, createHash, randomInt } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { createHttpClient } from '@arkenivajs/http';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { Settings, Destination } from './settings.js';
import type {
  WebhookService,
  WebhookContext,
  WebhookSignature,
  WebhookDelivery,
} from './contracts.js';
import {
  fields,
  text,
  instant,
  bytes,
  context as captureContext,
  signature as captureSignature,
  event as captureEvent,
  failure,
} from './validation.js';
import { mac, equal, replayKey } from './framing.js';
import { runtime } from './runtime.js';
import type { Call } from './runtime.js';
import { DnsBudget } from './dns-budget.js';

export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
/** Native DNS checks run inside the existing HTTP client's connect-time lookup. */
export function createService(
  settings: Settings,
  owner: AbortSignal,
  test: boolean,
  observer: Observers,
  ready: () => boolean,
) {
  if (!test && (settings.testOnly || settings.destinations.some((profile) => profile.cleartext)))
    throw failure();
  const calls = runtime(settings, owner, ready, () => dns.pending.size),
    profiles = new Map(settings.destinations.map((profile) => [profile.name, profile]));
  const dns = new DnsBudget(settings.maxConcurrent, calls.check);
  const clients = new Map(
    settings.destinations.map((profile) => [
      profile.name,
      createHttpClient({
        allowedOrigins: [profile.origin],
        allowPrivateNetwork: test,
        timeoutMs: profile.timeoutMs,
        connections: settings.maxConcurrent,
        maxResponseBytes: settings.maxOutputBytes,
        retry: { attempts: 1 },
        async resolve(hostname) {
          if (hostname !== profile.hostname) throw failure('EK_WEBHOOK_DELIVERY');
          const addresses = await dns.resolve(hostname);
          if (!addresses.length || addresses.some((item) => !profile.permits(item.address)))
            throw failure('EK_WEBHOOK_DELIVERY');
          return addresses.map((item) => ({ address: item.address, family: item.family as 4 | 6 }));
        },
      }),
    ]),
  );
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostic failures cannot repeat delivery or claims. */
    }
  };
  const profileFor = (name: string): Destination => {
    const profile = profiles.get(name);
    if (!profile) throw failure('EK_WEBHOOK_DELIVERY');
    return profile;
  };
  const observe = async <T>(
    operation: 'sign' | 'verify' | 'send',
    size: number,
    call: Call,
    work: () => Promise<T>,
  ): Promise<T> => {
    let outcome: 'ok' | 'error' = 'error';
    try {
      const result = await work();
      outcome =
        operation === 'send' && (result as WebhookDelivery).status !== 'accepted' ? 'error' : 'ok';
      return result;
    } finally {
      const attributes = { 'webhook.operation': operation, 'webhook.outcome': outcome };
      safe(() =>
        observer.logger?.debug('Webhook operation completed', { operation, outcome, bytes: size }),
      );
      safe(() =>
        observer.telemetry?.recordHistogram(
          'webhook.duration.ms',
          Math.max(0, performance.now() - call.started),
          attributes,
        ),
      );
      safe(() => observer.telemetry?.addCounter('webhook.payload.bytes', size, attributes));
      if (operation === 'verify' && outcome === 'error')
        safe(() => observer.telemetry?.addCounter('webhook.verification.failures', 1, attributes));
    }
  };
  async function tenant(
    call: Call,
    action: string,
    binding: Readonly<{ destinationId: string; eventId: string; keyId?: string }>,
  ): Promise<Readonly<{ issuer: string; subject: string; tenantId: string }>> {
    try {
      const result = await settings.require(
        action,
        undefined,
        Object.freeze({
          destinationId: binding.destinationId,
          eventId: binding.eventId,
          ...(binding.keyId === undefined ? {} : { keyId: binding.keyId }),
        }),
        call.options(),
      );
      call.check();
      const subject = fields(result, ['issuer', 'subject', 'tenant']);
      text(subject.issuer, 2048);
      text(subject.subject);
      if (subject.tenant === undefined)
        return Object.freeze({
          issuer: subject.issuer as string,
          subject: subject.subject as string,
          tenantId: '',
        });
      const tenant = fields(subject.tenant, ['tenantId', 'identity', 'verifiedAt', 'source']),
        identity = fields(tenant.identity, [
          'issuer',
          'subject',
          'audience',
          'scopes',
          'claims',
          'assurance',
        ]);
      if (
        identity.issuer !== subject.issuer ||
        identity.subject !== subject.subject ||
        !['oidc', 'service-identity'].includes(tenant.source as string) ||
        Date.parse(instant(tenant.verifiedAt)) > Date.now() + 300000
      )
        throw failure();
      return Object.freeze({
        issuer: subject.issuer as string,
        subject: subject.subject as string,
        tenantId: text(tenant.tenantId, 128),
      });
    } catch {
      call.check();
      throw failure('EK_AUTH_FORBIDDEN');
    }
  }
  function fresh(ctx: WebhookContext): void {
    if (Math.abs(Date.now() - Date.parse(ctx.timestamp)) > 300000)
      throw failure('EK_WEBHOOK_SIGNATURE');
  }
  async function key(call: Call, reference: string, expectedVersion?: string) {
    try {
      const secret = fields(await settings.get(reference, call.options()), [
        'bytes',
        'keyVersion',
        'expiresAt',
      ]);
      call.check();
      const version = text(secret.keyVersion, 128);
      if (
        (expectedVersion !== undefined && version !== expectedVersion) ||
        (secret.expiresAt !== undefined && Date.parse(instant(secret.expiresAt)) <= Date.now())
      )
        throw failure();
      const owned = bytes(secret.bytes as Uint8Array, 4096);
      if (owned.length < 32) {
        owned.fill(0);
        throw failure();
      }
      return { owned, version };
    } catch {
      call.check();
      throw failure('EK_WEBHOOK_SIGNATURE');
    }
  }
  async function signature(
    call: Call,
    raw: Buffer,
    ctx: WebhookContext,
    reference: string,
    tenantId: string,
  ): Promise<WebhookSignature> {
    const secret = await key(call, reference, ctx.keyId);
    try {
      call.check();
      fresh(ctx);
      return Object.freeze({
        algorithm: 'hmac-sha256',
        keyId: ctx.keyId,
        timestamp: ctx.timestamp,
        nonce: ctx.nonce,
        signature: mac(raw, ctx, tenantId, secret.owned),
      });
    } finally {
      secret.owned.fill(0);
    }
  }
  const service: WebhookService = Object.freeze<WebhookService>({
    async sign(input, keyRef, inputContext, options) {
      const raw = bytes(input, settings.maxInputBytes),
        ctx = captureContext(inputContext),
        profile = profileFor(ctx.destinationId),
        reference = text(keyRef);
      if (reference !== profile.hmacKeyRef) throw failure('EK_WEBHOOK_SIGNATURE');
      return calls.run(options, (call) =>
        observe('sign', raw.length, call, async () => {
          const principal = await tenant(call, 'webhooks.sign', ctx),
            tenantId = principal.tenantId;
          fresh(ctx);
          return signature(call, raw, ctx, reference, tenantId);
        }),
      );
    },
    async verify(input, inputSignature, inputContext, options) {
      const raw = bytes(input, settings.maxInputBytes),
        sig = captureSignature(inputSignature),
        ctx = captureContext(inputContext),
        profile = profileFor(ctx.destinationId);
      if (sig.keyId !== ctx.keyId || sig.timestamp !== ctx.timestamp || sig.nonce !== ctx.nonce)
        throw failure('EK_WEBHOOK_SIGNATURE');
      return calls.run(options, (call) =>
        observe('verify', raw.length, call, async () => {
          const principal = await tenant(call, 'webhooks.verify', ctx),
            tenantId = principal.tenantId;
          fresh(ctx);
          const retained = profile.verificationKeys.find((item) => item.keyId === ctx.keyId);
          if (retained && Date.parse(retained.expiresAt) <= Date.now())
            throw failure('EK_WEBHOOK_SIGNATURE');
          const expected = await signature(
            call,
            raw,
            ctx,
            retained?.hmacKeyRef ?? profile.hmacKeyRef,
            tenantId,
          );
          if (!equal(expected.signature, sig.signature)) throw failure('EK_WEBHOOK_SIGNATURE');
          call.check();
          fresh(ctx);
          call.sideEffectAttempted = true;
          let claimed: unknown;
          try {
            claimed = await settings.store.claimOnce(
              'webhooks.nonces.v1',
              replayKey(ctx, principal),
              new Date(Math.max(Date.now(), Date.parse(ctx.timestamp)) + 300001).toISOString(),
              call.options(settings.storeTimeoutMs),
            );
          } catch {
            call.check();
            throw failure('EK_WEBHOOK_REPLAY', true);
          }
          call.check();
          if (typeof claimed !== 'boolean') throw failure('EK_WEBHOOK_REPLAY', true);
          call.sideEffectAttempted = false;
          if (!claimed) throw failure('EK_WEBHOOK_REPLAY');
          return Object.freeze({
            destinationId: ctx.destinationId,
            eventId: ctx.eventId,
            verifiedAt: new Date().toISOString(),
          });
        }),
      );
    },
    async send(destinationId, input, options) {
      const profile = profileFor(text(destinationId, 64)),
        event = captureEvent(input, settings.maxInputBytes),
        encoded = JSON.stringify(event),
        raw = Buffer.from(encoded);
      return calls.run(options, (call) =>
        observe('send', raw.length, call, async () => {
          const principal = await tenant(call, 'webhooks.send', {
              destinationId: profile.name,
              eventId: event.id,
            }),
            tenantId = principal.tenantId;
          let attemptCount = 0;
          while (true) {
            call.check();
            const secret = await key(call, profile.hmacKeyRef),
              ctx: WebhookContext = Object.freeze({
                destinationId: profile.name,
                eventId: event.id,
                timestamp: new Date().toISOString(),
                nonce: randomBytes(24).toString('base64url'),
                keyId: secret.version,
              });
            let sig: WebhookSignature;
            try {
              sig = Object.freeze({
                algorithm: 'hmac-sha256',
                keyId: ctx.keyId,
                timestamp: ctx.timestamp,
                nonce: ctx.nonce,
                signature: mac(raw, ctx, tenantId, secret.owned),
              });
            } finally {
              secret.owned.fill(0);
            }
            call.check();
            attemptCount++;
            call.sideEffectAttempted = true;
            let result: WebhookDelivery['status'] = 'unknown',
              retry = true;
            try {
              const response = await clients.get(profile.name)!.request(profile.origin, {
                method: 'POST',
                body: encoded,
                ...call.options(profile.timeoutMs),
                redirect: 'manual',
                headers: {
                  'content-type': 'application/json',
                  'arkeniva-webhook-context': Buffer.from(JSON.stringify(ctx)).toString(
                    'base64url',
                  ),
                  'arkeniva-webhook-signature': 'v1,' + sig.signature,
                },
                ...(profile.idempotent
                  ? {
                      idempotencyKey: createHash('sha256')
                        .update(
                          JSON.stringify([
                            'arkenivajs.webhooks.delivery.v1',
                            tenantId,
                            profile.name,
                            event.id,
                          ]),
                        )
                        .digest('hex'),
                    }
                  : {}),
              });
              call.check();
              result = response.status >= 200 && response.status < 300 ? 'accepted' : 'rejected';
              retry = response.status === 429 || response.status >= 500;
            } catch {
              call.check();
            }
            safe(() =>
              observer.telemetry?.addCounter('webhook.delivery.attempts', 1, {
                'webhook.operation': 'send',
                'webhook.outcome': result === 'accepted' ? 'ok' : 'error',
              }),
            );
            if (!retry || !profile.idempotent || attemptCount > profile.maxRetries)
              return Object.freeze({
                destinationId: profile.name,
                eventId: event.id,
                status: result,
                attemptCount,
              });
            await delay(randomInt(50, 151), undefined, { signal: call.signal });
            call.check();
          }
        }),
      );
    },
    parseEvent(input) {
      calls.check();
      try {
        return captureEvent(
          JSON.parse(
            new TextDecoder('utf-8', { fatal: true }).decode(bytes(input, settings.maxInputBytes)),
          ),
          settings.maxInputBytes,
        );
      } catch {
        throw failure('EK_WEBHOOK_DELIVERY');
      }
    },
  });
  return {
    service,
    async close() {
      const draining = calls.close();
      void draining.catch(() => undefined);
      const closing = Promise.allSettled([...clients.values()].map((client) => client.close()));
      await draining;
      await dns.drain();
      await closing;
    },
  };
}
