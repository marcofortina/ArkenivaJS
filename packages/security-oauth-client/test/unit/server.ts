// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:http';
import type { RequestListener } from 'node:http';
import { createServer as createSecureServer } from 'node:https';
import { createHash, randomBytes } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

/** Controlled OAuth server uses actual requests, PKCE verification, signatures and token rotation. */
export async function startServer(tls?: Readonly<{ key: Buffer; cert: Buffer }>) {
  const signing = await generateKeyPair('RS256'),
    jwk = await exportJWK(signing.publicKey),
    kid = randomBytes(12).toString('hex'),
    clientId = 'controlled-oauth-client',
    secret = randomBytes(24).toString('base64url'),
    redirectUri = 'http://127.0.0.1:19090/callback?view=orders',
    audience = 'https://resource.fixture.invalid/orders',
    codes = new Map<
      string,
      { challenge: string; nonce: string; scope: string; resource: string }
    >(),
    refresh = new Map<string, { family: string; scope: string; resource: string }>(),
    tokenFamilies = new Map<string, string>(),
    revoked = new Set<string>(),
    metricExports: string[] = [],
    traceExports: string[] = [],
    counts = { discovery: 0, authorize: 0, token: 0, refresh: 0, revoke: 0, jwks: 0 };
  let issuer = '';
  const mode = {
    badNonce: false,
    badSignature: false,
    noRotation: false,
    wrongScope: false,
    unavailable: false,
    wrongIssuer: false,
    wrongAudience: false,
    expiredIdToken: false,
    wrongTokenType: false,
    invalidExpiry: false,
    noPkce: false,
    noRevocation: false,
    noAuthorization: false,
    foreignEndpoint: false,
    holdToken: undefined as Promise<void> | undefined,
    tokenRedirect: undefined as string | undefined,
    oversizedResponse: false,
    discoveryPayload: undefined as unknown,
    discoveryStatus: 200,
  };
  const token = () => randomBytes(32).toString('base64url');
  const handler: RequestListener = async (request, response) => {
    const send = (status: number, body: unknown) => {
      response.writeHead(status, {
        'content-type': 'application/json',
        'cache-control': 'no-store',
      });
      response.end(JSON.stringify(body));
    };
    try {
      const url = new URL(request.url ?? '/', issuer || 'http://127.0.0.1');
      if (['/v1/metrics', '/v1/traces'].includes(url.pathname) && request.method === 'POST') {
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          if (size > 1048576) throw new Error('Owned telemetry fixture input exceeds its limit');
          chunks.push(chunk);
        }
        (url.pathname === '/v1/metrics' ? metricExports : traceExports).push(
          Buffer.concat(chunks).toString('utf8'),
        );
        send(200, {});
        return;
      }
      if (url.pathname === '/.well-known/openid-configuration') {
        counts.discovery++;
        if (mode.discoveryPayload !== undefined || mode.discoveryStatus !== 200) {
          send(mode.discoveryStatus, mode.discoveryPayload ?? {});
          return;
        }
        send(200, {
          issuer,
          ...(mode.noAuthorization ? {} : { authorization_endpoint: issuer + '/authorize' }),
          token_endpoint: mode.foreignEndpoint
            ? 'https://unapproved.fixture.invalid/token'
            : issuer + '/token',
          jwks_uri: issuer + '/jwks',
          ...(mode.noRevocation ? {} : { revocation_endpoint: issuer + '/revoke' }),
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'],
          code_challenge_methods_supported: mode.noPkce ? ['plain'] : ['S256'],
          id_token_signing_alg_values_supported: ['RS256'],
          authorization_response_iss_parameter_supported: true,
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
        });
        return;
      }
      if (url.pathname === '/jwks') {
        counts.jwks++;
        send(200, { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });
        return;
      }
      if (url.pathname === '/authorize') {
        counts.authorize++;
        const query = url.searchParams;
        if (
          query.get('client_id') !== clientId ||
          query.get('redirect_uri') !== redirectUri ||
          query.get('response_type') !== 'code' ||
          query.get('code_challenge_method') !== 'S256' ||
          query.get('resource') !== audience
        ) {
          send(400, { error: 'invalid_request' });
          return;
        }
        const code = token();
        codes.set(code, {
          challenge: query.get('code_challenge') ?? '',
          nonce: query.get('nonce') ?? '',
          scope: query.get('scope') ?? '',
          resource: query.get('resource') ?? '',
        });
        const callback = new URL(redirectUri);
        callback.searchParams.set('code', code);
        callback.searchParams.set('state', query.get('state') ?? '');
        callback.searchParams.set('iss', issuer);
        response.writeHead(302, { location: callback.href, 'cache-control': 'no-store' });
        response.end();
        return;
      }
      if (request.method !== 'POST' || !['/token', '/revoke'].includes(url.pathname)) {
        send(404, { error: 'not_found' });
        return;
      }
      let size = 0;
      const chunks: Buffer[] = [];
      for await (const chunk of request) {
        const data = Buffer.from(chunk as Uint8Array);
        size += data.length;
        if (size > 65536) {
          request.destroy();
          return;
        }
        chunks.push(data);
      }
      const form = new URLSearchParams(Buffer.concat(chunks).toString());
      let authenticated = false;
      // OAuth Basic credentials use form encoding before base64, including encoded unreserved bytes.
      try {
        const header = request.headers.authorization ?? '';
        if (header.startsWith('Basic ') && header.length <= 8192) {
          const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8'),
            separator = decoded.indexOf(':');
          authenticated =
            separator >= 0 &&
            decodeURIComponent(decoded.slice(0, separator).replaceAll('+', ' ')) === clientId &&
            decodeURIComponent(decoded.slice(separator + 1).replaceAll('+', ' ')) === secret;
        }
      } catch {
        /* Malformed authentication is denied without exposing credential bytes. */
      }
      if (!authenticated) {
        send(401, { error: 'invalid_client' });
        return;
      }
      if (mode.unavailable) {
        send(503, { error: 'temporarily_unavailable' });
        return;
      }
      if (url.pathname === '/revoke') {
        counts.revoke++;
        const family = tokenFamilies.get(form.get('token') ?? '');
        if (family) revoked.add(family);
        send(200, {});
        return;
      }
      counts.token++;
      await mode.holdToken;
      if (mode.tokenRedirect) {
        response.writeHead(302, { location: mode.tokenRedirect });
        response.end();
        return;
      }
      if (mode.oversizedResponse) {
        send(200, { access_token: 'x'.repeat(300000), token_type: 'Bearer', expires_in: 300 });
        return;
      }
      const resource = form.get('resource') ?? '';
      let scope = form.get('scope') ?? '',
        nonce = '',
        family = token(),
        old: string | undefined;
      if (form.get('grant_type') === 'authorization_code') {
        const code = form.get('code') ?? '',
          record = codes.get(code);
        if (
          !record ||
          form.get('redirect_uri') !== redirectUri ||
          resource !== record.resource ||
          createHash('sha256')
            .update(form.get('code_verifier') ?? '')
            .digest('base64url') !== record.challenge
        ) {
          send(400, { error: 'invalid_grant' });
          return;
        }
        codes.delete(code);
        scope = record.scope;
        nonce = record.nonce;
      } else if (form.get('grant_type') === 'refresh_token') {
        counts.refresh++;
        old = form.get('refresh_token') ?? '';
        const record = refresh.get(old);
        if (!record || revoked.has(record.family) || resource !== record.resource) {
          send(400, { error: 'invalid_grant' });
          return;
        }
        family = record.family;
        scope = record.scope;
        refresh.delete(old);
      } else if (form.get('grant_type') !== 'client_credentials') {
        send(400, { error: 'unsupported_grant_type' });
        return;
      }
      if (resource !== audience) {
        send(400, { error: 'invalid_target' });
        return;
      }
      const access = 'access.' + token(),
        result: Record<string, unknown> = {
          access_token: access,
          token_type: mode.wrongTokenType ? 'Unknown' : 'Bearer',
          expires_in: mode.invalidExpiry ? 0 : 300,
          scope: mode.wrongScope ? 'admin' : scope,
        };
      if (form.get('grant_type') !== 'client_credentials') {
        const next = mode.noRotation && old ? old : 'refresh.' + token();
        refresh.set(next, { family, scope, resource });
        tokenFamilies.set(next, family);
        result.refresh_token = next;
      }
      if (scope.split(' ').includes('openid') && form.get('grant_type') === 'authorization_code') {
        result.id_token = await new SignJWT({ nonce: mode.badNonce ? 'wrong-nonce' : nonce })
          .setProtectedHeader({ alg: 'RS256', kid })
          .setIssuer(mode.wrongIssuer ? 'https://wrong.fixture.invalid' : issuer)
          .setSubject('controlled-resource-owner')
          .setAudience(mode.wrongAudience ? 'wrong-client' : clientId)
          .setIssuedAt()
          .setExpirationTime(mode.expiredIdToken ? '-2m' : '5m')
          .sign(signing.privateKey);
        if (mode.badSignature) {
          const parts = String(result.id_token).split('.');
          parts[2] = Buffer.alloc(256).toString('base64url');
          result.id_token = parts.join('.');
        }
      }
      send(200, result);
    } catch {
      if (!response.headersSent) send(500, { error: 'server_error' });
      else response.destroy();
    }
  };
  const server = tls ? createSecureServer(tls, handler) : createServer(handler);
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.maxConnections = 16;
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string')
    throw new Error('Owned OAuth server address unavailable');
  issuer = (tls ? 'https://' : 'http://') + '127.0.0.1:' + address.port;
  return {
    issuer,
    clientId,
    secret,
    redirectUri,
    audience,
    counts,
    mode,
    metricExports,
    traceExports,
    async authorize(url: string) {
      const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
      if (response.status !== 302) throw new Error('Controlled authorization failed');
      const callback = new URL(response.headers.get('location')!);
      return {
        stateRef: callback.searchParams.get('state')!,
        code: callback.searchParams.get('code')!,
        issuer: callback.searchParams.get('iss')!,
        redirectUri,
      };
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      codes.clear();
      refresh.clear();
      tokenFamilies.clear();
      revoked.clear();
    },
  };
}
