// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TLSSocket } from 'node:tls';
import { COMPONENTS } from '@arkenivajs/core';
import type { ApiServer, Plugin } from '@arkenivajs/core';
import type { MagicLinkService, MagicLinkIntent } from '@arkenivajs/security-magiclink';
import type { FastifyInstance, FastifyReply } from 'fastify';

const script = `const form = document.getElementById('confirmation');
const status = document.getElementById('status');
const fragment = new URLSearchParams(location.hash.slice(1));
const token = fragment.get('token');
const purpose = fragment.get('purpose');
history.replaceState(null, '', location.pathname);
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!token || !['login', 'email-verify', 'account-recover'].includes(purpose)) {
    status.textContent = 'The link could not be confirmed.';
    return;
  }
  try {
    const response = await fetch('/magic/consume', {
      method: 'POST', credentials: 'same-origin',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({token, purpose})
    });
    status.textContent = response.ok ? 'Confirmed.' : 'The link could not be confirmed.';
  } catch { status.textContent = 'The link could not be confirmed.'; }
});`;
const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Confirm your request</title><script src="/magiclink-confirmation.js" defer></script></head><body><h1>Confirm your request</h1><form id="confirmation" method="post" action="/magic/consume"><button type="submit">Confirm</button></form><p id="status" role="status"></p></body></html>`;
function headers(reply: FastifyReply): void {
  reply.header('referrer-policy', 'no-referrer');
  reply.header('cache-control', 'no-store');
  reply.header('x-content-type-options', 'nosniff');
  reply.header('x-frame-options', 'DENY');
  reply.header(
    'content-security-policy',
    "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );
}

/** Application-owned HTTPS confirmation, registered before the framework listener activates. */
export function magicLinkConfirmationPlugin(
  magic: MagicLinkService,
  trustedOrigin: string,
): Plugin {
  const origin = new URL(trustedOrigin);
  if (origin.protocol !== 'https:' || origin.origin !== trustedOrigin)
    throw new Error('The confirmation origin must be an explicit HTTPS origin');
  return {
    id: 'magiclink-confirmation',
    version: '1.0.0',
    capabilities: new Set(),
    dependencies: ['api'],
    init(context) {
      const server = context.require<ApiServer>(COMPONENTS.api).native() as FastifyInstance;
      const onRequest = async (_request: unknown, reply: FastifyReply) => {
        headers(reply);
      };
      server.get('/confirm', { onRequest }, async (_request, reply) =>
        reply.type('text/html; charset=utf-8').send(page),
      );
      server.get('/magiclink-confirmation.js', { onRequest }, async (_request, reply) =>
        reply.type('application/javascript; charset=utf-8').send(script),
      );
      server.post<{ Body: { token: string; purpose: MagicLinkIntent } }>(
        '/magic/consume',
        {
          onRequest,
          bodyLimit: 1024,
          schema: {
            body: {
              type: 'object',
              additionalProperties: false,
              required: ['token', 'purpose'],
              properties: {
                token: { type: 'string', minLength: 84, maxLength: 84 },
                purpose: { enum: ['login', 'email-verify', 'account-recover'] },
              },
            },
          },
        },
        async (request, reply) => {
          if (
            !(request.raw.socket instanceof TLSSocket) ||
            !request.raw.socket.encrypted ||
            request.headers.origin !== origin.origin
          )
            return reply.code(400).send({ confirmed: false });
          const controller = new AbortController(),
            aborted = () => controller.abort(),
            closed = () => {
              if (!reply.raw.writableFinished) controller.abort();
            };
          request.raw.once('aborted', aborted);
          reply.raw.once('close', closed);
          try {
            await magic.consume(
              request.body.token,
              { method: request.method as 'POST', purpose: request.body.purpose },
              { signal: controller.signal },
            );
            return reply.send({ confirmed: true });
          } catch {
            return reply.code(400).send({ confirmed: false });
          } finally {
            request.raw.off('aborted', aborted);
            reply.raw.off('close', closed);
            controller.abort();
          }
        },
      );
    },
    close() {},
  };
}
