// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { mock } from 'node:test';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { createServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import {
  SignJWT,
  CompactEncrypt,
  exportJWK,
  calculateJwkThumbprint,
  jwtVerify,
  decodeJwt,
} from 'jose';
import { calculatePKCECodeChallenge } from 'openid-client';
import { FederationOidcCallback } from '../../dist/oidc-callback.js';
import { FederationOidcLogin } from '../../dist/oidc-login.js';
import { FederationProtocolHttp } from '../../dist/protocol-http.js';
import { capture } from '../../dist/settings.js';
import { configurationEndpoint } from '../../dist/resolver.js';
import { membershipFixture, op, sa, pairs, statement } from './membership.js';
import { transactionFixture } from './transactions.js';
import { registration } from './registration.js';
import { checkMapping } from './mapping-checks.js';
import { runPublicOidc } from './public-oidc-worker.js';

type Mode =
  | 'valid'
  | 'higher'
  | 'nonce'
  | 'id-signature'
  | 'audience'
  | 'loa'
  | 'hash'
  | 'hash-equal-length'
  | 'access-signature'
  | 'access-audience'
  | 'access-client'
  | 'plain-id'
  | 'plain-info'
  | 'info-signature'
  | 'info-subject'
  | 'wrong-id-encryption'
  | 'wrong-info-encryption'
  | 'id-audience-array'
  | 'id-nbf-mismatch'
  | 'id-jti'
  | 'id-issued-future'
  | 'id-expired'
  | 'access-jti'
  | 'access-scope'
  | 'access-issued-future'
  | 'info-audience-array'
  | 'info-issued-future'
  | 'info-expired'
  | 'info-object'
  | 'info-long'
  | 'info-array'
  | 'info-omitted';
process.once(
  'message',
  (input: {
    certificate: string;
    privateKey: string;
    mapping?: boolean;
    public?: boolean;
    telemetryMode?: 'standard' | 'detailed';
  }) => {
    void (input.public ? runPublicOidc(input) : run(input)).then(
      (result) => {
        process.send?.({
          ok: true,
          mode: result && result.publicFlow ? 'public' : input.mapping ? 'mapping' : 'callback',
        });
        process.disconnect();
      },
      (error: unknown) => {
        process.send?.({
          ok: false,
          message: error instanceof Error ? error.message : 'OIDC callback fixture failed',
        });
        process.disconnect();
      },
    );
  },
);
async function run(files: {
  certificate: string;
  privateKey: string;
  mapping?: boolean;
  public?: boolean;
}) {
  const f = await transactionFixture(),
    canonical = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    rp = generateKeyPairSync('rsa', { modulusLength: 2048 }),
    encryption = generateKeyPairSync('rsa', { modulusLength: 2048 }),
    provider = generateKeyPairSync('rsa', { modulusLength: 2048 }),
    foreign = generateKeyPairSync('rsa', { modulusLength: 2048 }),
    providerJwk = {
      ...(await exportJWK(provider.publicKey)),
      kid: 'op-protocol',
      alg: 'RS512',
      use: 'sig',
    },
    recipientKid = await calculateJwkThumbprint(await exportJWK(encryption.publicKey)),
    codes = new Map<string, { nonce: string; challenge: string; mode: Mode; used: boolean }>(),
    access = new Map<string, { mode: Mode; subject: string }>();
  let origin = '',
    tokenRequests = 0,
    userInfoRequests = 0,
    serverFailure: Error | undefined,
    jwksRequests = 0,
    jwksFault = 'none';
  const encrypt = (value: string, purpose: 'id' | 'userinfo' = 'userinfo') =>
      new CompactEncrypt(new TextEncoder().encode(value))
        .setProtectedHeader({
          alg: purpose === 'id' ? 'RSA-OAEP' : 'RSA-OAEP-256',
          enc: purpose === 'id' ? 'A128CBC-HS256' : 'A256CBC-HS512',
          kid: recipientKid,
          cty: 'JWT',
        })
        .encrypt(encryption.publicKey),
    server = createServer(
      { key: await readFile(files.privateKey), cert: await readFile(files.certificate) },
      (request, response) => {
        void (async () => {
          let body = '';
          for await (const chunk of request) body += String(chunk);
          if (request.url === '/accounts-jwks') {
            response.setHeader('content-type', 'application/jwk-set+json');
            response.end(
              JSON.stringify({
                keys: [
                  {
                    ...(await exportJWK(canonical.publicKey)),
                    kid: 'canonical-public',
                    alg: 'ES256',
                    use: 'sig',
                  },
                ],
              }),
            );
            return;
          }
          if (request.url === '/jwks' || request.url === '/signed-jwks') {
            jwksRequests++;
            assert.equal(request.headers.authorization, undefined);
            assert.equal(request.headers.cookie, undefined);
            const keys = [{ ...providerJwk, ...(jwksFault === 'private' ? { d: 'inert' } : {}) }];
            if (request.url === '/jwks') {
              response.setHeader('content-type', 'application/jwk-set+json');
              response.end(JSON.stringify({ keys }));
              return;
            }
            const now = Math.floor(Date.now() / 1000),
              token = await new SignJWT({
                iss: jwksFault === 'issuer' ? 'https://foreign.example.test' : op,
                sub: op,
                keys,
                ...(jwksFault === 'no-time'
                  ? {}
                  : {
                      iat: jwksFault === 'future' ? now + 100 : now,
                      exp: jwksFault === 'expired' ? now - 1 : now + 120,
                    }),
                ...(jwksFault === 'critical' ? { crit: ['unrecognized'] } : {}),
              })
                .setProtectedHeader({
                  typ: jwksFault === 'type' ? 'JWT' : 'jwk-set+jwt',
                  alg: 'ES256',
                  kid: 'public-2',
                })
                .sign(pairs[jwksFault === 'signature' ? 4 : 2]!.privateKey);
            response.setHeader('content-type', 'application/jwk-set+jwt');
            response.end(token);
            return;
          }
          if (request.url === '/token') {
            tokenRequests++;
            const form = new URLSearchParams(body),
              record = codes.get(form.get('code') ?? '');
            assert.ok(record && !record.used);
            record.used = true;
            assert.equal(form.get('grant_type'), 'authorization_code');
            assert.equal(form.get('client_id'), f.profile.clientId);
            assert.equal(form.get('redirect_uri'), f.profile.redirectUri + '?application=fixture');
            assert.equal(
              form.get('client_assertion_type'),
              'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            );
            const assertion = await jwtVerify(form.get('client_assertion')!, rp.publicKey, {
              algorithms: ['RS256'],
              issuer: f.profile.clientId!,
              subject: f.profile.clientId!,
              audience: origin + '/token',
            });
            assert.ok(
              typeof assertion.payload.jti === 'string' && assertion.payload.jti.length > 20,
            );
            assert.equal(
              await calculatePKCECodeChallenge(form.get('code_verifier')!),
              record.challenge,
            );
            const now = Math.floor(Date.now() / 1000),
              subject = 'upstream-subject',
              accessToken = await new SignJWT({
                client_id:
                  record.mode === 'access-client'
                    ? 'https://foreign.example.test'
                    : f.profile.clientId,
                scope: record.mode === 'access-scope' ? 'unapproved' : 'openid',
                jti: record.mode === 'access-jti' ? 'not-a-version-four-identifier' : randomUUID(),
              })
                .setProtectedHeader({ alg: 'RS512', kid: 'op-protocol', typ: 'at+jwt' })
                .setIssuer(op)
                .setSubject(subject)
                .setAudience(
                  record.mode === 'access-audience'
                    ? 'https://foreign.example.test/userinfo'
                    : origin + '/userinfo',
                )
                .setIssuedAt(record.mode === 'access-issued-future' ? now + 30 : now)
                .setExpirationTime(now + 120)
                .sign(
                  record.mode === 'access-signature' ? foreign.privateKey : provider.privateKey,
                ),
              atHash = createHash('sha512')
                .update(accessToken, 'ascii')
                .digest()
                .subarray(0, 32)
                .toString('base64url'),
              id = await new SignJWT({
                nonce: record.mode === 'nonce' ? 'a'.repeat(64) : record.nonce,
                acr:
                  'https://www.spid.gov.it/SpidL' +
                  (record.mode === 'loa' ? 1 : record.mode === 'higher' ? 3 : 2),
                at_hash:
                  record.mode === 'hash'
                    ? 'wrong-hash'
                    : record.mode === 'hash-equal-length'
                      ? (atHash.startsWith('A') ? 'B' : 'A') + atHash.slice(1)
                      : atHash,
                nbf: record.mode === 'id-nbf-mismatch' ? now - 1 : now,
                jti: record.mode === 'id-jti' ? 'not-a-version-four-identifier' : randomUUID(),
              })
                .setProtectedHeader({ alg: 'RS512', kid: 'op-protocol', cty: 'JWT' })
                .setIssuer(op)
                .setSubject(subject)
                .setAudience(
                  record.mode === 'audience'
                    ? 'https://foreign.example.test'
                    : record.mode === 'id-audience-array'
                      ? [f.profile.clientId!, 'https://unapproved.example.test']
                      : f.profile.clientId!,
                )
                .setIssuedAt(record.mode === 'id-issued-future' ? now + 30 : now)
                .setExpirationTime(record.mode === 'id-expired' ? now - 1 : now + 120)
                .sign(record.mode === 'id-signature' ? foreign.privateKey : provider.privateKey);
            access.set(accessToken, { mode: record.mode, subject });
            response.setHeader('content-type', 'application/json');
            response.end(
              JSON.stringify({
                access_token: accessToken,
                id_token:
                  record.mode === 'plain-id'
                    ? id
                    : await encrypt(id, record.mode === 'wrong-id-encryption' ? 'userinfo' : 'id'),
                token_type: 'Bearer',
                expires_in: 120,
              }),
            );
            return;
          }
          if (request.url === '/userinfo') {
            userInfoRequests++;
            const record = access.get(request.headers.authorization?.slice(7) ?? '');
            assert.ok(record);
            const token = await new SignJWT({
              ...(record.mode === 'info-omitted'
                ? {}
                : {
                    name:
                      record.mode === 'info-object'
                        ? { untrusted: 'value' }
                        : record.mode === 'info-long'
                          ? 'x'.repeat(4097)
                          : record.mode === 'info-array'
                            ? ['Fixture', 'Member']
                            : 'Fixture Member',
                  }),
              email_verified: true,
              age: 42,
              family_name: 'Native',
              sub: record.mode === 'info-subject' ? 'foreign-subject' : record.subject,
            })
              .setProtectedHeader({ alg: 'RS512', kid: 'op-protocol' })
              .setIssuer(op)
              .setAudience(
                record.mode === 'info-audience-array'
                  ? [f.profile.clientId!, 'https://unapproved.example.test']
                  : f.profile.clientId!,
              )
              .setIssuedAt(
                record.mode === 'info-issued-future'
                  ? Math.floor(Date.now() / 1000) + 30
                  : Math.floor(Date.now() / 1000),
              )
              .setExpirationTime(
                record.mode === 'info-expired'
                  ? Math.floor(Date.now() / 1000) - 1
                  : Math.floor(Date.now() / 1000) + 120,
              )
              .sign(record.mode === 'info-signature' ? foreign.privateKey : provider.privateKey);
            response.setHeader('content-type', 'application/jwt');
            response.end(
              record.mode === 'plain-info'
                ? token
                : await encrypt(token, record.mode === 'wrong-info-encryption' ? 'id' : 'userinfo'),
            );
            return;
          }
          throw new Error('Unexpected native protocol destination');
        })().catch((error: unknown) => {
          serverFailure = error instanceof Error ? error : new Error('Native fixture failed');
          response.writeHead(500, { 'content-type': 'application/json' });
          response.end('{"error":"fixture_failure"}');
        });
      },
    );
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  origin = `https://127.0.0.1:${address.port}`;
  const liveStatus = { status: 'active' };
  const metadata = {
      issuer: op,
      authorization_endpoint: op + '/authorize',
      token_endpoint: origin + '/token',
      userinfo_endpoint: origin + '/userinfo',
      jwks: { keys: [providerJwk] },
      scopes_supported: ['openid'],
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      request_object_signing_alg_values_supported: ['RS256'],
      acr_values_supported: ['https://www.spid.gov.it/SpidL2', 'https://www.spid.gov.it/SpidL3'],
      client_registration_types_supported: ['automatic'],
      claims_parameter_supported: true,
      request_parameter_supported: true,
      token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      id_token_signing_alg_values_supported: ['RS512'],
      userinfo_signing_alg_values_supported: ['RS512'],
      id_token_encryption_alg_values_supported: ['RSA-OAEP'],
      id_token_encryption_enc_values_supported: ['A128CBC-HS256'],
      userinfo_encryption_alg_values_supported: ['RSA-OAEP-256'],
      userinfo_encryption_enc_values_supported: ['A256CBC-HS512'],
    },
    graph = await membershipFixture({
      op: { metadata: { openid_provider: metadata } },
      status: liveStatus,
    }),
    profile = {
      ...graph.profile,
      redirectUri: f.profile.redirectUri + '?application=fixture',
      oidcRegistration: {
        ...(await registration(graph.profile.entityId)),
        idTokenEncryption: {
          algorithm: 'RSA-OAEP' as const,
          encryption: 'A128CBC-HS256' as const,
        },
        requestedClaims: ['name', 'family_name', 'email_verified', 'age'],
        approvedProtocolEndpoints: [
          origin + '/token',
          origin + '/userinfo',
          origin + '/jwks',
          origin + '/signed-jwks',
        ],
      },
    },
    settings = capture({ ...f.settings, profiles: [profile] }, 'test'),
    transport = new FederationProtocolHttp(settings, profile.profileId),
    callback = new FederationOidcCallback(
      settings,
      profile.profileId,
      graph.http,
      transport,
      f.crypto,
    ),
    login = new FederationOidcLogin(settings, profile.profileId, graph.http, f.crypto);
  graph.records.set(configurationEndpoint(op), graph.leafConfiguration);
  f.material.set('signing-ref', {
    bytes: Buffer.from(rp.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  f.material.set('oidc-decryption-ref', {
    bytes: Buffer.from(encryption.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  const begin = async (
    mode: Mode,
    tenantHint = files.mapping ? 'tenant-A' : 'unverified-tenant',
  ) => {
    const initiated = await f.runtime.run((call) =>
        login.begin(call, {
          issuer: op,
          assurance: 'spid-l2',
          returnPath: '/private',
          tenantHint,
        }),
      ),
      request = await jwtVerify(
        new URL(initiated.redirectUrl).searchParams.get('request')!,
        rp.publicKey,
        { issuer: profile.entityId, audience: op, algorithms: ['RS256'] },
      ),
      code = randomUUID(),
      url = new URL(profile.redirectUri);
    codes.set(code, {
      nonce: String(request.payload.nonce),
      challenge: String(request.payload.code_challenge),
      mode,
      used: false,
    });
    url.searchParams.set('code', code);
    url.searchParams.set('state', initiated.transactionId);
    url.searchParams.set('iss', op);
    return url;
  };
  try {
    const incoming = await begin('valid'),
      result = await f.runtime.run((call) => callback.consume(call, incoming.href));
    assert.equal(callback.result(result), result);
    assert.equal(result.issuer, op);
    assert.equal(result.subject, 'upstream-subject');
    assert.equal(result.assurance, 'spid-l2');
    assert.deepEqual(result.attributes.name, ['Fixture Member']);
    assert.deepEqual(result.attributes.email_verified, ['true']);
    assert.deepEqual(result.attributes.age, ['42']);
    assert.equal(result.returnPath, '/private');
    assert.equal(result.tenantHint, files.mapping ? 'tenant-A' : 'unverified-tenant');
    assert.equal('access_token' in result, false);
    assert.equal('nonce' in result, false);
    assert.equal('verifier' in result, false);
    if (files.mapping) {
      await checkMapping(
        origin,
        canonical.privateKey,
        f.settings,
        profile,
        callback,
        result,
        f.runtime,
        async (hint) => {
          const target = await begin('valid', hint);
          return f.runtime.run((call) => callback.consume(call, target.href));
        },
      );
      return;
    }
    mock.timers.enable({ apis: ['Date'], now: Date.now() });
    mock.timers.tick(40000);
    assert.throws(() => callback.result(result), { code: 'EK_EID_FEDERATION' });
    mock.timers.reset();
    assert.throws(() => callback.result({ ...result }), { code: 'EK_EID_FEDERATION' });
    assert.throws(
      () =>
        new FederationOidcCallback(
          settings,
          profile.profileId,
          graph.http,
          transport,
          f.crypto,
        ).result(result),
      { code: 'EK_EID_FEDERATION' },
    );
    const before = tokenRequests;
    await assert.rejects(() => f.runtime.run((call) => callback.consume(call, incoming.href)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(tokenRequests, before);
    const higher = await f.runtime.run(async (call) =>
      callback.consume(call, (await begin('higher')).href),
    );
    assert.equal(higher.assurance, 'spid-l3');
    for (const mode of ['info-array', 'info-omitted'] as const) {
      const target = await begin(mode),
        verified = await f.runtime.run((call) => callback.consume(call, target.href));
      if (mode === 'info-array') assert.deepEqual(verified.attributes.name, ['Fixture', 'Member']);
      else assert.equal(Object.hasOwn(verified.attributes, 'name'), false);
    }
    for (const mode of [
      'nonce',
      'id-signature',
      'audience',
      'loa',
      'hash',
      'hash-equal-length',
      'access-signature',
      'access-audience',
      'access-client',
      'plain-id',
      'plain-info',
      'info-signature',
      'info-subject',
      'wrong-id-encryption',
      'wrong-info-encryption',
      'id-audience-array',
      'id-nbf-mismatch',
      'id-jti',
      'id-issued-future',
      'id-expired',
      'access-jti',
      'access-scope',
      'access-issued-future',
      'info-audience-array',
      'info-issued-future',
      'info-expired',
      'info-object',
      'info-long',
    ] as const) {
      const target = await begin(mode);
      await assert.rejects(() => f.runtime.run((call) => callback.consume(call, target.href)), {
        code: mode === 'loa' ? 'EK_EID_ASSURANCE' : 'EK_EID_FEDERATION',
      });
      const issued = tokenRequests;
      await assert.rejects(() => f.runtime.run((call) => callback.consume(call, target.href)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(tokenRequests, issued);
    }
    const concurrent = await begin('valid'),
      issued = tokenRequests,
      attempts = await Promise.allSettled(
        Array.from({ length: 8 }, () =>
          f.runtime.run((call) => callback.consume(call, concurrent.href)),
        ),
      );
    assert.equal(attempts.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(tokenRequests, issued + 1);
    const malformed = await begin('valid'),
      sent = tokenRequests;
    for (const mutate of [
      (value: URL) => {
        value.hostname = 'foreign.example.test';
      },
      (value: URL) => {
        value.searchParams.append('state', value.searchParams.get('state')!);
      },
      (value: URL) => {
        value.searchParams.set('iss', 'https://foreign.example.test');
      },
      (value: URL) => {
        value.searchParams.set('application', 'foreign');
      },
    ]) {
      const target = new URL(malformed);
      mutate(target);
      await assert.rejects(() => f.runtime.run((call) => callback.consume(call, target.href)));
    }
    assert.equal(tokenRequests, sent);
    let effects = 0;
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          callback.consume(call, {
            get href() {
              effects++;
              return malformed.href;
            },
          }),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(effects, 0);
    const denied = await begin('valid'),
      beforeError = tokenRequests;
    const errorResponse = new URL(denied);
    errorResponse.searchParams.delete('code');
    errorResponse.searchParams.set('error', 'access_denied');
    await assert.rejects(
      () => f.runtime.run((call) => callback.consume(call, errorResponse.href)),
      { code: 'EK_EID_FEDERATION' },
    );
    await assert.rejects(() => f.runtime.run((call) => callback.consume(call, denied.href)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(tokenRequests, beforeError);
    const lost = await begin('valid'),
      beforeLost = tokenRequests;
    f.state.ambiguousClaim = true;
    await assert.rejects(() => f.runtime.run((call) => callback.consume(call, lost.href)), {
      code: 'EK_EID_FEDERATION',
    });
    f.state.ambiguousClaim = false;
    await assert.rejects(() => f.runtime.run((call) => callback.consume(call, lost.href)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(tokenRequests, beforeLost);
    for (const outage of ['storage', 'secrets'] as const) {
      const target = await begin('valid'),
        before = tokenRequests;
      f.state[outage] = false;
      await assert.rejects(() => f.runtime.run((call) => callback.consume(call, target.href)), {
        code: 'EK_EID_FEDERATION',
      });
      f.state[outage] = true;
      assert.equal(tokenRequests, before);
    }
    const withdrawn = await begin('valid'),
      beforeRevoked = tokenRequests;
    liveStatus.status = 'revoked';
    await assert.rejects(() => f.runtime.run((call) => callback.consume(call, withdrawn.href)), {
      code: 'EK_EID_FEDERATION',
    });
    liveStatus.status = 'active';
    assert.equal(tokenRequests, beforeRevoked);
    const keySource = async (source: 'inline' | 'remote' | 'signed' | 'both') => {
      const resolved = {
        ...metadata,
        ...(source === 'inline' || source === 'both' ? {} : { jwks: undefined }),
        ...(source === 'remote'
          ? { jwks_uri: origin + '/jwks' }
          : source === 'signed'
            ? { signed_jwks_uri: origin + '/signed-jwks' }
            : source === 'both'
              ? { jwks_uri: 'https://unapproved.example.test/keys' }
              : {}),
      };
      graph.records.set(
        configurationEndpoint(op),
        await statement(op, op, 2, 2, {
          ...decodeJwt<Record<string, unknown>>(graph.leafConfiguration),
          authority_hints: [sa],
          metadata: { openid_provider: resolved },
        }),
      );
    };
    for (const source of ['remote', 'signed', 'both'] as const) {
      await keySource(source);
      jwksFault = 'none';
      const before = jwksRequests,
        target = await begin('valid'),
        result = await f.runtime.run((call) => callback.consume(call, target.href));
      assert.equal(callback.result(result).subject, 'upstream-subject');
      assert.equal(jwksRequests, before + (source === 'both' ? 0 : 1));
    }
    await keySource('signed');
    jwksFault = 'no-time';
    const optionalTimes = await begin('valid'),
      bounded = await f.runtime.run((call) => callback.consume(call, optionalTimes.href));
    assert.ok(Date.parse(bounded.expiresAt) <= Date.now() + 30000);
    for (const fault of [
      'signature',
      'issuer',
      'type',
      'expired',
      'future',
      'critical',
      'private',
    ]) {
      jwksFault = fault;
      const target = await begin('valid'),
        before = tokenRequests;
      await assert.rejects(() => f.runtime.run((call) => callback.consume(call, target.href)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(tokenRequests, before, 'Invalid signed keys cannot reach the token endpoint');
    }
    await keySource('remote');
    jwksFault = 'private';
    const privateRemote = await begin('valid');
    await assert.rejects(
      () => f.runtime.run((call) => callback.consume(call, privateRemote.href)),
      { code: 'EK_EID_FEDERATION' },
    );
    await keySource('inline');
    jwksFault = 'none';
    const late = await begin('valid');
    let release!: () => void, entered!: () => void;
    const pending = new Promise<void>((resolve) => {
        release = resolve;
      }),
      began = new Promise<void>((resolve) => {
        entered = resolve;
      }),
      delayed = new FederationOidcCallback(
        settings,
        profile.profileId,
        {
          ...graph.http,
          async trustMarkStatus(endpoint, token, options) {
            entered();
            await pending;
            return graph.http.trustMarkStatus(endpoint, token, options);
          },
        },
        transport,
        f.crypto,
      );
    try {
      const work = f.runtime.run((call) => delayed.consume(call, late.href), { timeoutMs: 200 }),
        rejected = assert.rejects(work, { code: 'EK_TIMEOUT' });
      await began;
      await rejected;
      assert.equal(f.runtime.stats().active, 1);
    } finally {
      release();
    }

    assert.equal(serverFailure, undefined);
    assert.ok(userInfoRequests >= 3);
  } finally {
    mock.timers.reset();
    await transport.close();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await f.close();
  }
}
