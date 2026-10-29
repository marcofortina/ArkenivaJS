// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { createServer } from 'node:https';
import { createServer as createCollector } from 'node:http';
import { Writable } from 'node:stream';
import { readFile } from 'node:fs/promises';
import {
  generateKeyPair,
  SignJWT,
  CompactEncrypt,
  exportJWK,
  exportSPKI,
  jwtVerify,
  calculateJwkThumbprint,
} from 'jose';
import { calculatePKCECodeChallenge } from 'openid-client';
import { createApplication } from '@arkenivajs/core';
import type { Application } from '@arkenivajs/core';
import { HEALTH_PROBES } from '@arkenivajs/core/support';
import type { PluginHealthProbe } from '@arkenivajs/core/support';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import type { ManagedAuthService } from '@arkenivajs/security';
import { cryptoPlugin } from '@arkenivajs/security-crypto';
import { spidPlugin, SPID_CAPABILITY } from '../../dist/index.js';
import type { ItalianEidPluginSettings, SpidService } from '../../dist/index.js';
import { transactionFixture } from './transactions.js';

interface MetricPoint {
  readonly attributes: readonly { key: string; value: { stringValue?: string } }[];
  readonly asDouble?: number;
  readonly asInt?: string;
}
interface Metric {
  readonly name: string;
  readonly sum?: { dataPoints: readonly MetricPoint[] };
}
interface Envelope {
  readonly resourceMetrics?: readonly { scopeMetrics: readonly { metrics: readonly Metric[] }[] }[];
}

export async function runPublicOidc(files: {
  certificate: string;
  privateKey: string;
  telemetryMode?: 'standard' | 'detailed';
}) {
  const base = await transactionFixture(),
    rootPair = await generateKeyPair('ES256'),
    opPair = await generateKeyPair('ES256'),
    rpPair = generateKeyPairSync('rsa', { modulusLength: 2048 }),
    decryptPair = generateKeyPairSync('rsa', { modulusLength: 2048 }),
    opProtocol = generateKeyPairSync('rsa', { modulusLength: 2048 }),
    canonical = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    rotated = generateKeyPairSync('rsa', { modulusLength: 2048 }),
    signingJwk = {
      ...(await exportJWK(rpPair.publicKey)),
      kid: await calculateJwkThumbprint(await exportJWK(rpPair.publicKey)),
      alg: 'RS256',
      use: 'sig',
    },
    rootJwk = {
      ...(await exportJWK(rootPair.publicKey)),
      kid: 'root-public',
      alg: 'ES256',
      use: 'sig',
    },
    opJwk = {
      ...(await exportJWK(opPair.publicKey)),
      kid: 'op-federation',
      alg: 'ES256',
      use: 'sig',
    },
    protocolJwk = {
      ...(await exportJWK(opProtocol.publicKey)),
      kid: 'op-protocol',
      alg: 'RS512',
      use: 'sig',
    },
    decKid = await calculateJwkThumbprint(await exportJWK(decryptPair.publicKey)),
    codes = new Map<string, { nonce: string; challenge: string; used: boolean }>(),
    envelopes: Envelope[] = [],
    logs: string[] = [],
    markers: string[] = [],
    destination = new Writable({
      write(chunk: Buffer, _encoding, done) {
        logs.push(chunk.toString('utf8'));
        done();
      },
    }),
    collector = createCollector(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      envelopes.push(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Envelope);
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    });
  await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
  const collectorAddress = collector.address();
  assert.ok(collectorAddress && typeof collectorAddress === 'object');
  let origin = '',
    root = '',
    op = '',
    rp = '',
    rpMark = '',
    opMark = '',
    rootRequests = 0,
    tokenRequests = 0,
    userInfoRequests = 0,
    serverFailure: Error | undefined,
    health: PluginHealthProbe | undefined;
  const state = {
    rpActive: true,
    opActive: true,
    beginAllowed: true,
    rotateSigning: false,
    rotateDecrypt: false,
    signingReads: 0,
    decryptionReads: 0,
    statusGate: undefined as { entered: () => void; wait: Promise<void> } | undefined,
  };
  const token = (
      issuer: string,
      subject: string | undefined,
      type: string,
      claims: Record<string, unknown>,
      signer = rootPair.privateKey,
      kid = 'root-public',
    ) =>
      new SignJWT({
        iss: issuer,
        ...(subject ? { sub: subject } : {}),
        iat: Math.floor(Date.now() / 1000) - 1,
        exp: Math.floor(Date.now() / 1000) + 300,
        ...claims,
      })
        .setProtectedHeader({ typ: type, alg: 'ES256', kid })
        .sign(signer),
    encrypt = (value: string, purpose: 'id' | 'userinfo') =>
      new CompactEncrypt(new TextEncoder().encode(value))
        .setProtectedHeader({
          alg: purpose === 'id' ? 'RSA-OAEP' : 'RSA-OAEP-256',
          enc: purpose === 'id' ? 'A128CBC-HS256' : 'A256CBC-HS512',
          kid: decKid,
          cty: 'JWT',
        })
        .encrypt(decryptPair.publicKey),
    server = createServer(
      { key: await readFile(files.privateKey), cert: await readFile(files.certificate) },
      (request, response) => {
        void (async () => {
          let body = '';
          for await (const chunk of request) body += String(chunk);
          const target = new URL(request.url!, origin);
          if (target.pathname === '/canonical-jwks') {
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
          if (target.pathname.startsWith('/root/')) {
            rootRequests++;
            assert.equal(request.headers.authorization, undefined);
            assert.equal(request.headers.cookie, undefined);
            if (target.pathname === '/root/.well-known/openid-federation') {
              response.setHeader('content-type', 'application/entity-statement+jwt');
              response.end(
                await token(root, root, 'entity-statement+jwt', {
                  jwks: { keys: [rootJwk] },
                  constraints: { max_path_length: 0 },
                  trust_mark_issuers: {
                    [origin + '/openid_relying_party/public/']: [root],
                    [origin + '/openid_provider/public/']: [root],
                  },
                  metadata: {
                    federation_entity: {
                      federation_fetch_endpoint: root + '/fetch',
                      federation_trust_mark_status_endpoint: root + '/status',
                    },
                  },
                }),
              );
              return;
            }
            if (target.pathname === '/root/fetch') {
              const subject = target.searchParams.get('sub');
              assert.ok(subject === rp || subject === op);
              response.setHeader('content-type', 'application/entity-statement+jwt');
              response.end(
                await token(root, subject, 'entity-statement+jwt', {
                  jwks: { keys: [subject === rp ? signingJwk : opJwk] },
                }),
              );
              return;
            }
            if (target.pathname === '/root/status') {
              if (state.statusGate) {
                state.statusGate.entered();
                await state.statusGate.wait;
              }
              const submitted = new URLSearchParams(body).get('trust_mark');
              assert.ok(submitted === rpMark || submitted === opMark);
              response.setHeader('content-type', 'application/trust-mark-status-response+jwt');
              response.end(
                await token(root, undefined, 'trust-mark-status-response+jwt', {
                  trust_mark: submitted,
                  status: (submitted === rpMark ? state.rpActive : state.opActive)
                    ? 'active'
                    : 'revoked',
                }),
              );
              return;
            }
          }
          if (target.pathname === '/provider/.well-known/openid-federation') {
            response.setHeader('content-type', 'application/entity-statement+jwt');
            response.end(await providerConfiguration());
            return;
          }
          if (target.pathname === '/provider/token') {
            tokenRequests++;
            const form = new URLSearchParams(body),
              record = codes.get(form.get('code') ?? '');
            assert.ok(record && !record.used);
            record.used = true;
            assert.equal(form.get('redirect_uri'), rp + '/callback?application=fixture');
            assert.equal(form.get('client_id'), rp);
            assert.equal(form.get('grant_type'), 'authorization_code');
            await jwtVerify(form.get('client_assertion')!, rpPair.publicKey, {
              algorithms: ['RS256'],
              issuer: rp,
              subject: rp,
              audience: op + '/token',
            });
            assert.equal(
              await calculatePKCECodeChallenge(form.get('code_verifier')!),
              record.challenge,
            );
            const now = Math.floor(Date.now() / 1000),
              access = await new SignJWT({ client_id: rp, scope: 'openid', jti: randomUUID() })
                .setProtectedHeader({ alg: 'RS512', kid: 'op-protocol', typ: 'at+jwt' })
                .setIssuer(op)
                .setSubject('upstream-subject')
                .setAudience(op + '/userinfo')
                .setIssuedAt(now)
                .setExpirationTime(now + 120)
                .sign(opProtocol.privateKey),
              id = await new SignJWT({
                nonce: record.nonce,
                acr: 'https://www.spid.gov.it/SpidL2',
                at_hash: createHash('sha512')
                  .update(access, 'ascii')
                  .digest()
                  .subarray(0, 32)
                  .toString('base64url'),
                nbf: now,
                jti: randomUUID(),
              })
                .setProtectedHeader({ alg: 'RS512', kid: 'op-protocol', cty: 'JWT' })
                .setIssuer(op)
                .setSubject('upstream-subject')
                .setAudience(rp)
                .setIssuedAt(now)
                .setExpirationTime(now + 120)
                .sign(opProtocol.privateKey);
            response.setHeader('content-type', 'application/json');
            response.end(
              JSON.stringify({
                access_token: access,
                id_token: id,
                token_type: 'Bearer',
                expires_in: 120,
              }),
            );
            return;
          }
          if (target.pathname === '/provider/userinfo') {
            userInfoRequests++;
            assert.ok(request.headers.authorization?.startsWith('Bearer '));
            const signed = await new SignJWT({ name: 'Public Fixture' })
              .setProtectedHeader({ alg: 'RS512', kid: 'op-protocol' })
              .setIssuer(op)
              .setSubject('upstream-subject')
              .setAudience(rp)
              .setIssuedAt()
              .setExpirationTime('2m')
              .sign(opProtocol.privateKey);
            response.setHeader('content-type', 'application/jwt');
            response.end(await encrypt(signed, 'userinfo'));
            return;
          }
          throw new Error('Unexpected public fixture destination');
        })().catch((error: unknown) => {
          serverFailure = error instanceof Error ? error : new Error('Public fixture failed');
          response.writeHead(500, { 'content-type': 'application/json' });
          response.end('{"error":"fixture_failure"}');
        });
      },
    );
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  origin = `https://127.0.0.1:${address.port}`;
  root = origin + '/root';
  op = origin + '/provider';
  rp = origin + '/rp';
  rpMark = await token(root, rp, 'trust-mark+jwt', {
    id: origin + '/openid_relying_party/public/',
  });
  opMark = await token(root, op, 'trust-mark+jwt', { id: origin + '/openid_provider/public/' });
  const providerConfiguration = () =>
      token(
        op,
        op,
        'entity-statement+jwt',
        {
          jwks: { keys: [opJwk] },
          authority_hints: [root],
          trust_marks: [{ id: origin + '/openid_provider/public/', trust_mark: opMark }],
          metadata: {
            openid_provider: {
              issuer: op,
              authorization_endpoint: op + '/authorize',
              token_endpoint: op + '/token',
              userinfo_endpoint: op + '/userinfo',
              jwks: { keys: [protocolJwk] },
              scopes_supported: ['openid'],
              response_types_supported: ['code'],
              code_challenge_methods_supported: ['S256'],
              request_object_signing_alg_values_supported: ['RS256'],
              acr_values_supported: ['https://www.spid.gov.it/SpidL2'],
              client_registration_types_supported: ['automatic'],
              request_parameter_supported: true,
              claims_parameter_supported: true,
              token_endpoint_auth_methods_supported: ['private_key_jwt'],
              token_endpoint_auth_signing_alg_values_supported: ['RS256'],
              id_token_signing_alg_values_supported: ['RS512'],
              userinfo_signing_alg_values_supported: ['RS512'],
              userinfo_encryption_alg_values_supported: ['RSA-OAEP-256'],
              userinfo_encryption_enc_values_supported: ['A256CBC-HS512'],
            },
          },
        },
        opPair.privateKey,
        'op-federation',
      ),
    profile = {
      ...base.profile,
      profileId: 'public-profile',
      entityId: rp,
      clientId: rp,
      redirectUri: rp + '/callback?application=fixture',
      expectedIssuers: [op],
      metadata: {
        ...base.profile.metadata,
        trustAnchors: [
          {
            issuer: root,
            kid: 'root-public',
            publicKeyPem: await exportSPKI(rootPair.publicKey),
            validFrom: new Date(Date.now() - 60000).toISOString(),
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          },
        ],
        approvedMetadataEndpoints: [
          root + '/.well-known/openid-federation',
          root + '/fetch',
          root + '/status',
          op + '/.well-known/openid-federation',
        ],
        refreshIntervalSeconds: 60,
      },
      oidcRegistration: {
        authorityHints: [root],
        trustMarks: [rpMark],
        organization: {
          organizationName: 'Public Fixture Organization',
          homepageUri: origin,
          policyUri: origin + '/policy',
          contacts: ['office@example.test'],
          resolveEndpoint: origin + '/resolve',
        },
        signingAlgorithm: 'RS256' as const,
        idTokenSigningAlgorithm: 'RS512' as const,
        userInfoSigningAlgorithm: 'RS512' as const,
        decryptionKeyRef: 'oidc-decryption-ref',
        userInfoEncryption: {
          algorithm: 'RSA-OAEP-256' as const,
          encryption: 'A256CBC-HS512' as const,
        },
        requestedClaims: ['name'],
        approvedProtocolEndpoints: [op + '/token', op + '/userinfo'],
      },
    },
    settings: ItalianEidPluginSettings = {
      ...base.settings,
      profiles: [
        profile,
        {
          ...profile,
          profileId: 'alternate-profile',
          expectedIssuers: [op, origin + '/secondary-provider'],
        },
      ],
      policy: { maxConcurrent: 8, timeoutMs: 5000, maxInputBytes: 65536, maxOutputBytes: 65536 },
      secretProvider: Object.freeze({
        usage: 'test-only',
        async get(reference: string) {
          if (reference === 'signing-ref') {
            state.signingReads++;
            if (state.rotateSigning && state.signingReads === 2)
              return {
                bytes: Buffer.from(rotated.privateKey.export({ format: 'pem', type: 'pkcs8' })),
                keyVersion: 'rotated',
              };
          }
          if (reference === 'oidc-decryption-ref') {
            state.decryptionReads++;
            if (state.rotateDecrypt && state.decryptionReads === 2)
              return {
                bytes: Buffer.from(rotated.privateKey.export({ format: 'pem', type: 'pkcs8' })),
                keyVersion: 'rotated',
              };
          }
          return base.settings.secretProvider.get(reference);
        },
      }),
      identityMappers: {
        [profile.tenantMappingId]: {
          async map(input) {
            assert.equal(input.issuer, op);
            assert.equal(input.subject, 'upstream-subject');
            const auth = app!.auth as ManagedAuthService,
              bearer = await new SignJWT({ tenant_id: 'tenant-A', scope: 'application:read' })
                .setProtectedHeader({ alg: 'ES256', kid: 'canonical-public', typ: 'JWT' })
                .setIssuer(origin + '/accounts')
                .setSubject('canonical-account')
                .setAudience('api://canonical-identity')
                .setIssuedAt()
                .setExpirationTime('2m')
                .sign(canonical.privateKey),
              identity = await auth.verifyBearer('Bearer ' + bearer),
              tenant = auth.tenantFrom(identity);
            return {
              issuer: identity.issuer,
              subject: identity.subject,
              tenant,
              assurance: input.assurance,
            };
          },
        },
      },
      authority: {
        async require(action, subject, context) {
          if (action === 'spid.begin_authentication') {
            assert.equal(subject, undefined);
            if (!state.beginAllowed) throw new Error('Anonymous ceremony denied');
            return { issuer: rp, subject: 'ceremony-policy' };
          }
          assert.equal(action, 'spid.consume_authentication');
          assert.ok(subject);
          assert.ok((app!.auth as ManagedAuthService).isVerifiedTenant(context.tenant));
          assert.equal(subject.tenant, context.tenant);
          return subject;
        },
      },
    };
  base.material.set('signing-ref', {
    bytes: Buffer.from(rpPair.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  base.material.set('oidc-decryption-ref', {
    bytes: Buffer.from(decryptPair.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  const app: Application = await createApplication({
    service: { name: 'public-spid-fixture', version: '1.0.0', environment: 'test' },
    logging: { level: 'debug' },
    telemetry: { mode: files.telemetryMode ?? 'detailed', samplingRatio: 1 },
    security: {
      issuer: origin + '/accounts',
      audience: 'api://canonical-identity',
      algorithms: ['ES256'],
    },
    plugins: [
      loggingPlugin({ destination }),
      telemetryPlugin({
        endpoint: 'http://127.0.0.1:' + collectorAddress.port,
        allowInsecureLoopback: true,
        exportIntervalMs: 60000,
        exportTimeoutMs: 1000,
      }),
      securityPlugin({
        jwksUrl: origin + '/canonical-jwks',
        allowedJwksOrigins: [origin],
        allowInsecureLoopback: true,
      }),
      cryptoPlugin({
        secrets: base.settings.secretProvider,
        encryptionKeyRefs: base.settings.stateEncryptionKeyRefs!,
        signingKeyRefs: base.settings.stateMacKeyRefs!,
        policy: { maxConcurrent: 32, timeoutMs: 5000, maxInputBytes: 65536, maxOutputBytes: 65536 },
      }),
      spidPlugin(settings),
      {
        id: 'spid-readiness-probe',
        version: '1.0.0',
        dependencies: ['spid'],
        capabilities: new Set(['health']),
        async init(context) {
          health = context
            .require<readonly PluginHealthProbe[]>(HEALTH_PROBES)
            .find((probe) => probe.name === 'plugin.spid');
          assert.ok(health);
          assert.equal(await health.check({ timeoutMs: 5000 }), true);
          const service = context
              .require<SpidService>(SPID_CAPABILITY)
              .forProfile(profile.profileId),
            before = rootRequests;
          await assert.rejects(() => service.metadata(), { code: 'EK_LIFECYCLE_STATE' });
          await assert.rejects(
            () => service.beginAuthentication({ returnPath: '/private' }, 'spid-l2'),
            {
              code: 'EK_LIFECYCLE_STATE',
            },
          );
          assert.equal(rootRequests, before);
        },
        close() {},
      },
    ],
  });
  try {
    await app.start();
    assert.ok(health);
    assert.equal(await health.check({ timeoutMs: 5000 }), true);
    base.state.storage = false;
    assert.equal(await health.check({ timeoutMs: 5000 }), false);
    base.state.storage = true;
    const rootService = app.resolve<SpidService>(SPID_CAPABILITY),
      service = rootService.forProfile(profile.profileId);
    assert.equal(service, rootService.forProfile(profile.profileId));
    assert.throws(() => rootService.forProfile('missing-profile'), { code: 'EK_EID_PROFILE' });
    await assert.rejects(() => rootService.metadata(), { code: 'EK_EID_PROFILE' });
    const before = rootRequests;
    await assert.rejects(
      () => rootService.beginAuthentication({ returnPath: '/private' }, 'spid-l2'),
      { code: 'EK_EID_PROFILE' },
    );
    assert.equal(rootRequests, before);
    await assert.rejects(
      () =>
        rootService
          .forProfile('alternate-profile')
          .beginAuthentication({ returnPath: '/private' }, 'spid-l2'),
      { code: 'EK_EID_ASSURANCE' },
    );
    state.beginAllowed = false;
    const denied = rootRequests;
    await assert.rejects(() => service.beginAuthentication({ returnPath: '/private' }, 'spid-l2'), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(rootRequests, denied);
    state.beginAllowed = true;
    const count = state.signingReads,
      metadata = await service.metadata();
    assert.equal(state.signingReads, count + 1);
    await jwtVerify(metadata, rpPair.publicKey, {
      algorithms: ['RS256'],
      issuer: rp,
      subject: rp,
      typ: 'entity-statement+jwt',
    });
    const begin = async () => {
      const login = await service.beginAuthentication(
          { returnPath: '/private', tenantId: 'tenant-A', issuer: op },
          'spid-l2',
        ),
        request = await jwtVerify(
          new URL(login.redirectUrl).searchParams.get('request')!,
          rpPair.publicKey,
          { issuer: rp, audience: op },
        ),
        code = randomUUID(),
        target = new URL(profile.redirectUri);
      codes.set(code, {
        nonce: String(request.payload.nonce),
        challenge: String(request.payload.code_challenge),
        used: false,
      });
      markers.push(
        code,
        login.transactionId,
        String(request.payload.nonce),
        new URL(login.redirectUrl).searchParams.get('request')!,
      );
      target.searchParams.set('code', code);
      target.searchParams.set('state', login.transactionId);
      target.searchParams.set('iss', op);
      return target;
    };
    const incoming = await begin(),
      identity = await service.consumeAuthentication(incoming.href);
    assert.equal(identity.issuer, origin + '/accounts');
    assert.equal(identity.subject, 'canonical-account');
    assert.equal(identity.claims.tenant_id, 'tenant-A');
    assert.equal(identity.federationAssurance, 'spid-l2');
    assert.deepEqual(identity.attributes.name, ['Public Fixture']);
    assert.equal(identity.assurance, undefined);
    assert.equal(tokenRequests, 1);
    assert.equal(userInfoRequests, 1);
    await assert.rejects(() => service.consumeAuthentication(incoming.href), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(tokenRequests, 1);
    assert.equal(
      (await service.verifyFederationTrust(await providerConfiguration())).trusted,
      true,
    );
    assert.equal((await service.verifyFederationTrust('invalid-statement')).trusted, false);
    let release!: () => void, entered!: () => void;
    const wait = new Promise<void>((resolve) => {
        release = resolve;
      }),
      arrived = new Promise<void>((resolve) => {
        entered = resolve;
      }),
      controller = new AbortController();
    state.statusGate = { entered, wait };
    try {
      const pending = service.verifyFederationTrust(await providerConfiguration(), {
          signal: controller.signal,
        }),
        rejected = assert.rejects(pending, { code: 'EK_ABORTED' });
      await arrived;
      controller.abort();
      await rejected;
    } finally {
      state.statusGate = undefined;
      release();
    }
    state.rpActive = false;
    assert.equal(await health.check({ timeoutMs: 5000 }), false);
    await assert.rejects(() => service.beginAuthentication({ returnPath: '/private' }, 'spid-l2'), {
      code: 'EK_EID_FEDERATION',
    });
    state.rpActive = true;
    assert.equal(await health.check({ timeoutMs: 5000 }), true);
    state.rotateSigning = true;
    state.signingReads = 0;
    await assert.rejects(() => service.beginAuthentication({ returnPath: '/private' }, 'spid-l2'), {
      code: 'EK_EID_FEDERATION',
    });
    state.rotateSigning = false;
    const rotatedCallback = await begin(),
      issued = tokenRequests;
    state.rotateDecrypt = true;
    state.decryptionReads = 0;
    await assert.rejects(() => service.consumeAuthentication(rotatedCallback.href), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(tokenRequests, issued);
    state.rotateDecrypt = false;
    const concurrent = await begin(),
      attempts = await Promise.allSettled(
        Array.from({ length: 8 }, () => service.consumeAuthentication(concurrent.href)),
      );
    assert.equal(attempts.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(serverFailure, undefined);
    await app.telemetry.flush();
    await app.logger.flush();
    const metrics = envelopes
      .flatMap((envelope) => envelope.resourceMetrics ?? [])
      .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics))
      .filter((metric) => metric.name.startsWith('spid.'));
    assert.deepEqual([...new Set(metrics.map((metric) => metric.name))].sort(), [
      'spid.handshakes',
      'spid.trust.failures',
    ]);
    const handshakes = metrics
      .filter((metric) => metric.name === 'spid.handshakes')
      .flatMap((metric) => metric.sum?.dataPoints ?? [])
      .reduce((total, point) => total + (point.asDouble ?? Number(point.asInt ?? 0)), 0);
    assert.equal(
      handshakes,
      20,
      'Internal federation steps cannot duplicate public handshake attempts',
    );
    const points = metrics.flatMap((metric) => metric.sum?.dataPoints ?? []);
    assert.ok(
      points.some((point) =>
        point.attributes.some(
          (attribute) => attribute.key === 'spid.outcome' && attribute.value.stringValue === 'ok',
        ),
      ),
    );
    assert.ok(
      points.some((point) =>
        point.attributes.some(
          (attribute) =>
            attribute.key === 'spid.outcome' && attribute.value.stringValue === 'federation',
        ),
      ),
    );
    for (const point of points)
      for (const attribute of point.attributes)
        assert.ok(['spid.operation', 'spid.outcome'].includes(attribute.key));
    const serialized = JSON.stringify({ envelopes, logs });
    for (const marker of [
      ...markers,
      rp,
      root,
      op,
      profile.profileId,
      'tenant-A',
      'canonical-account',
      'upstream-subject',
      '/private',
      'signing-ref',
      'oidc-decryption-ref',
      'BEGIN PRIVATE KEY',
      metadata,
    ])
      assert.equal(serialized.includes(marker), false, 'Sensitive federation data was exported');
    await app.stop();
    await assert.rejects(() => service.metadata(), { code: 'EK_RESOURCE_CLOSED' });
    return { publicFlow: true as const };
  } finally {
    await app.stop();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    collector.closeAllConnections();
    await new Promise<void>((resolve) => collector.close(() => resolve()));
    destination.end();
    await base.close();
  }
}
