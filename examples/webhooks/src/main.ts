// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application, Identity } from '@arkenivajs/core';
import { createAuthService } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { webhooksPlugin, WEBHOOKS_CAPABILITY } from '@arkenivajs/webhooks';
import type { WebhookService, WebhookContext, WebhookSignature } from '@arkenivajs/webhooks';
import { disposableStore } from './disposable-store.js';

/** Exercise real OIDC, native HMAC, HTTP delivery, replay denial and actual private SDK exports. */
export async function runWebhooksExample() {
  const pair = await generateKeyPair('ES256'),
    jwk = {
      ...(await exportJWK(pair.publicKey)),
      alg: 'ES256',
      use: 'sig',
      kid: 'webhooks-example',
    },
    hmac = randomBytes(32),
    authentication = new AsyncLocalStorage<Identity>(),
    logs: string[] = [],
    envelopes: {
      resourceMetrics?: { scopeMetrics: { metrics: { name: string; unit: string }[] }[] }[];
    }[] = [];
  let authority = '',
    receiverToken = '',
    app: Application | undefined,
    auth: Awaited<ReturnType<typeof createAuthService>> | undefined,
    webhooks: WebhookService | undefined,
    deliveries = 0,
    last: { raw: Buffer; context: WebhookContext; signature: WebhookSignature } | undefined;
  const authenticated = async <T>(token: string, work: () => Promise<T>): Promise<T> => {
    const identity = await auth!.verifyBearer(token);
    return authentication.run(identity, work);
  };
  const server = createServer((request, response) => {
    void (async () => {
      response.setHeader('content-type', 'application/json');
      if (request.url === '/keys') {
        response.end(JSON.stringify({ keys: [jwk] }));
        return;
      }
      if (request.url === '/.well-known/openid-configuration') {
        response.end(JSON.stringify({ issuer: authority, jwks_uri: authority + '/keys' }));
        return;
      }
      const chunks: Buffer[] = [];
      let length = 0;
      for await (const chunk of request) {
        length += chunk.length;
        if (length > 1048576) throw new Error('Disposable receiver input overflow');
        chunks.push(chunk);
      }
      const raw = Buffer.concat(chunks);
      if (request.url === '/v1/metrics') {
        envelopes.push(JSON.parse(raw.toString('utf8')));
        response.end('{}');
        return;
      }
      if (request.url !== '/' || request.method !== 'POST') {
        response.statusCode = 404;
        response.end('{}');
        return;
      }
      const context = JSON.parse(
          Buffer.from(String(request.headers['arkeniva-webhook-context']), 'base64url').toString(
            'utf8',
          ),
        ) as WebhookContext,
        signature: WebhookSignature = {
          algorithm: 'hmac-sha256',
          keyId: context.keyId,
          nonce: context.nonce,
          timestamp: context.timestamp,
          signature: String(request.headers['arkeniva-webhook-signature']).slice(3),
        };
      // The receiver authorizes its own tenant-bound service principal independently of input headers.
      await authenticated(receiverToken, () => webhooks!.verify(raw, signature, context));
      last = { raw, context, signature };
      deliveries++;
      response.statusCode = 202;
      response.end('{}');
    })().catch((error: unknown) => {
      response.statusCode =
        error instanceof KitError && error.code === 'EK_WEBHOOK_REPLAY' ? 409 : 401;
      response.end('{}');
    });
  });
  const destination = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs.push(chunk.toString('utf8'));
      done();
    },
  });
  try {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address !== 'object')
      throw new Error('Disposable webhook listener unavailable');
    authority = 'http://127.0.0.1:' + address.port;
    auth = await createAuthService({
      issuer: authority,
      audience: 'api://webhooks-example',
      environment: 'test',
      algorithms: ['ES256'],
      allowInsecureLoopback: true,
      authorizeTenant: (_identity, tenantId) => tenantId === 'example-tenant',
    });
    const token = async (subject: string, scope: string) =>
      'Bearer ' +
      (await new SignJWT({ tenant_id: 'example-tenant', scope })
        .setProtectedHeader({ alg: 'ES256', kid: 'webhooks-example', typ: 'JWT' })
        .setIssuer(authority)
        .setAudience('api://webhooks-example')
        .setSubject(subject)
        .setExpirationTime('2m')
        .sign(pair.privateKey));
    const senderToken = await token('example-sender', 'webhooks:send');
    receiverToken = await token('example-receiver', 'webhooks:verify');
    app = await createApplication({
      service: { name: 'webhooks-example', version: '0.1.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      plugins: [
        loggingPlugin({ destination }),
        telemetryPlugin({
          endpoint: authority,
          allowInsecureLoopback: true,
          exportIntervalMs: 1000,
          exportTimeoutMs: 1000,
        }),
        webhooksPlugin({
          destinations: [
            {
              name: 'receiver',
              origin: authority,
              hmacKeyRef: 'fixture/webhooks',
              allowedCidrs: ['127.0.0.1/32'],
              maxRetries: 0,
              timeoutMs: 3000,
            },
          ],
          policy: {
            maxConcurrent: 4,
            timeoutMs: 5000,
            maxInputBytes: 65536,
            maxOutputBytes: 65536,
          },
          nonceStore: {
            store: disposableStore(),
            securityLevel: 'test-only',
            operationTimeoutMs: 1000,
          },
          secretProvider: {
            async get(reference) {
              if (reference !== 'fixture/webhooks')
                throw new Error('Unknown disposable key reference');
              return { bytes: hmac, keyVersion: 'one' };
            },
          },
          authority: {
            async require(action, _subject, context) {
              if (context.destinationId !== 'receiver')
                throw new Error('Unapproved receiver destination');
              const identity = authentication.getStore();
              if (!identity) throw new Error('Verified runtime principal required');
              auth!.requireScope(identity, action.replace('.', ':'));
              const tenant = auth!.tenantFrom(identity);
              if (!auth!.isVerifiedTenant(tenant))
                throw new Error('Verified tenant membership required');
              return { issuer: identity.issuer, subject: identity.subject, tenant };
            },
          },
        }),
      ],
    });
    await app.start();
    webhooks = app.resolve<WebhookService>(WEBHOOKS_CAPABILITY);
    let unauthenticatedDenied = false;
    const event = {
      id: 'example-event',
      type: 'order.created',
      payload: { private: 'private-webhook-content' },
    };
    try {
      await webhooks.send('receiver', event);
    } catch (error) {
      unauthenticatedDenied = error instanceof KitError && error.code === 'EK_AUTH_FORBIDDEN';
    }
    const receipt = await authenticated(senderToken, () => webhooks!.send('receiver', event));
    if (!last) throw new Error('No signed delivery was observed');
    const replay = await fetch(authority, {
      method: 'POST',
      body: new Uint8Array(last.raw),
      headers: {
        'content-type': 'application/json',
        'arkeniva-webhook-context': Buffer.from(JSON.stringify(last.context)).toString('base64url'),
        'arkeniva-webhook-signature': 'v1,' + last.signature.signature,
      },
    });
    const replayDenied = replay.status === 409;
    await replay.arrayBuffer();
    await app.telemetry.flush();
    await app.logger.flush();
    const privateValues = [
        'private-webhook-content',
        senderToken,
        receiverToken,
        last.signature.signature,
        last.context.nonce,
        hmac.toString('hex'),
      ],
      metrics = envelopes
        .flatMap((entry) => entry.resourceMetrics ?? [])
        .flatMap((entry) => entry.scopeMetrics)
        .flatMap((entry) => entry.metrics),
      wire = JSON.stringify(envelopes);
    return Object.freeze({
      accepted: receipt.status === 'accepted',
      attempts: receipt.attemptCount,
      deliveries,
      unauthenticatedDenied,
      replayDenied,
      logsPrivate: !privateValues.some((value) => logs.join('').includes(value)),
      metricsObserved:
        metrics.some(
          (metric) => metric.name === 'webhook.delivery.attempts' && metric.unit === '{attempt}',
        ) && metrics.some((metric) => metric.name === 'webhook.verification.failures'),
      metricsPrivate: ![
        ...privateValues,
        'example-tenant',
        'example-sender',
        'example-receiver',
      ].some((value) => wire.includes(value)),
    });
  } finally {
    try {
      await app?.stop();
    } finally {
      try {
        await auth?.close();
      } finally {
        authentication.disable();
        hmac.fill(0);
        destination.destroy();
        server.closeAllConnections();
        if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(await runWebhooksExample()));
