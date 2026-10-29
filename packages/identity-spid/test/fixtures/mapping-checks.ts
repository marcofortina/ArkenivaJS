// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { mock } from 'node:test';
import type { KeyObject } from 'node:crypto';
import { SignJWT } from 'jose';
import { createAuthService } from '@arkenivajs/security';
import type { FederationProfileV1, ItalianEidPluginSettings } from '../../dist/index.js';
import { capture } from '../../dist/settings.js';
import { FederationIdentityMapping } from '../../dist/identity-mapping.js';
import { FederationOidcCallback } from '../../dist/oidc-callback.js';
import type { VerifiedOidcResult } from '../../dist/oidc-callback.js';
import type { FederationRuntime } from '../../dist/runtime.js';

export async function checkMapping(
  origin: string,
  key: KeyObject,
  raw: ItalianEidPluginSettings,
  profile: FederationProfileV1,
  callback: FederationOidcCallback,
  proof: VerifiedOidcResult,
  runtime: FederationRuntime,
  freshHint: (hint: string) => Promise<VerifiedOidcResult>,
) {
  const options = {
      issuer: origin + '/accounts',
      audience: 'api://canonical-identity',
      jwksUrl: origin + '/accounts-jwks',
      allowedJwksOrigins: [origin],
      algorithms: ['ES256'],
      environment: 'test' as const,
      allowInsecureLoopback: true,
      clockToleranceSeconds: 0,
    },
    auth = await createAuthService(options),
    other = await createAuthService(options),
    bearer = async (tenant: string) =>
      'Bearer ' +
      (await new SignJWT({ tenant_id: tenant, scope: 'application:read' })
        .setProtectedHeader({ alg: 'ES256', kid: 'canonical-public', typ: 'JWT' })
        .setIssuer(options.issuer)
        .setAudience(options.audience)
        .setSubject('canonical-account')
        .setIssuedAt()
        .setExpirationTime('2m')
        .sign(key));
  let mapped: unknown,
    authorityMode = 'allow',
    mappingCalls = 0,
    authorityCalls = 0,
    effects = 0;
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => {
      release = resolve;
    }),
    began = new Promise<void>((resolve) => {
      entered = resolve;
    });
  try {
    const identity = await auth.verifyBearer(await bearer('tenant-A')),
      tenant = auth.tenantFrom(identity),
      tenantB = auth.tenantFrom(await auth.verifyBearer(await bearer('tenant-B'))),
      foreign = other.tenantFrom(await other.verifyBearer(await bearer('tenant-A'))),
      valid = {
        issuer: identity.issuer,
        subject: identity.subject,
        tenant,
        assurance: proof.assurance,
      };
    mapped = valid;
    const settings = capture(
        {
          ...raw,
          profiles: [profile],
          identityMappers: {
            [profile.tenantMappingId]: {
              async map(input, options) {
                mappingCalls++;
                assert.equal(input.profileId, profile.profileId);
                assert.equal(input.issuer, proof.issuer);
                assert.equal(input.subject, proof.subject);
                assert.ok(Object.isFrozen(input.attributes));
                assert.ok(options?.signal instanceof AbortSignal);
                if (mapped instanceof Error) throw mapped;
                return mapped as Awaited<
                  ReturnType<ItalianEidPluginSettings['identityMappers'][string]['map']>
                >;
              },
            },
          },
          authority: {
            async require(action, subject, context, options) {
              authorityCalls++;
              assert.equal(action, 'spid.consume_authentication');
              assert.ok(subject);
              assert.equal(subject.issuer, identity.issuer);
              assert.equal(subject.subject, identity.subject);
              assert.ok(auth.isVerifiedTenant(context.tenant));
              assert.equal(subject.tenant, context.tenant);
              assert.ok(options?.signal instanceof AbortSignal);
              if (authorityMode === 'deny') throw new Error('Private authorization diagnostic');
              if (authorityMode === 'foreign') return { ...subject, subject: 'foreign-account' };
              if (authorityMode === 'clone') return { ...subject, tenant: { ...tenant } };
              if (authorityMode === 'tenant-b') return { ...subject, tenant: tenantB };
              if (authorityMode === 'identity-only')
                return { issuer: subject.issuer, subject: subject.subject };
              if (authorityMode === 'close-auth') await auth.close();
              if (authorityMode === 'wait') {
                entered();
                await pending;
              }
              if (authorityMode === 'getter')
                return {
                  get issuer() {
                    effects++;
                    return identity.issuer;
                  },
                  subject: identity.subject,
                };
              return subject;
            },
          },
        },
        'test',
      ),
      mapping = new FederationIdentityMapping(settings, profile.profileId, callback, auth);
    const result = await runtime.run((call) => mapping.map(call, proof));
    assert.equal(result.issuer, identity.issuer);
    assert.equal(result.subject, identity.subject);
    assert.equal(result.claims.tenant_id, 'tenant-A');
    assert.equal(result.federationAssurance, proof.assurance);
    assert.deepEqual(result.attributes.name, ['Fixture Member']);
    assert.ok(Object.isFrozen(result));
    assert.equal(result.assurance, undefined);
    assert.deepEqual(result.scopes, ['application:read']);
    assert.equal(mappingCalls, 1);
    assert.equal(authorityCalls, 1);
    assert.equal(auth.isVerifiedTenant({ tenantId: 'tenant-A', identity }), false);
    authorityMode = 'identity-only';
    assert.equal(
      (await runtime.run((call) => mapping.map(call, proof))).claims.tenant_id,
      'tenant-A',
    );
    authorityMode = 'allow';
    const limited = new FederationIdentityMapping(
      { ...settings, policy: { ...settings.policy, maxOutputBytes: 1 } },
      profile.profileId,
      callback,
      auth,
    );
    await assert.rejects(() => runtime.run((call) => limited.map(call, proof)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.throws(
      () => new FederationIdentityMapping(settings, 'missing-profile', callback, auth),
      { code: 'EK_EID_PROFILE' },
    );
    assert.throws(
      () =>
        new FederationIdentityMapping(
          settings,
          profile.profileId,
          {} as FederationOidcCallback,
          auth,
        ),
      { code: 'EK_EID_PROFILE' },
    );
    for (const invalid of [
      { ...valid, tenant: { ...tenant } },
      { ...valid, tenant: foreign },
      { ...valid, tenant: tenantB },
      { ...valid, issuer: 'https://foreign.example.test' },
      { ...valid, subject: 'foreign-account' },
      { ...valid, assurance: 'spid-l3' },
      new Error('Private mapper diagnostic'),
      {
        ...valid,
        get tenant() {
          effects++;
          return tenant;
        },
      },
      new Proxy(valid, {
        ownKeys() {
          effects++;
          return [];
        },
      }),
    ]) {
      mapped = invalid;
      const before: number = authorityCalls;
      await assert.rejects(() => runtime.run((call) => mapping.map(call, proof)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(authorityCalls, before);
    }
    mapped = valid;
    for (const mode of ['deny', 'foreign', 'clone', 'tenant-b', 'getter']) {
      authorityMode = mode;
      await assert.rejects(() => runtime.run((call) => mapping.map(call, proof)), {
        code: 'EK_EID_FEDERATION',
      });
    }
    authorityMode = 'allow';
    assert.equal(effects, 0);
    const before: number = mappingCalls;
    await assert.rejects(() => runtime.run((call) => mapping.map(call, { ...proof })), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(mappingCalls, before);
    const fake = Object.create(FederationOidcCallback.prototype) as FederationOidcCallback;
    const fabricated = { ...proof };
    Reflect.set(fake, 'owned', new WeakMap([[fabricated, () => {}]]));
    const fakeMapping = new FederationIdentityMapping(settings, profile.profileId, fake, auth);
    await assert.rejects(() => runtime.run((call) => fakeMapping.map(call, fabricated)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(mappingCalls, before);
    const otherProfile = { ...profile, profileId: 'other-profile' },
      cross = capture({ ...raw, profiles: [profile, otherProfile] }, 'test'),
      crossMapping = new FederationIdentityMapping(cross, otherProfile.profileId, callback, auth);
    await assert.rejects(() => runtime.run((call) => crossMapping.map(call, proof)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(mappingCalls, before);
    const hint = await freshHint('tenant-B');
    await assert.rejects(() => runtime.run((call) => mapping.map(call, hint)), {
      code: 'EK_EID_FEDERATION',
    });
    mock.timers.enable({ apis: ['Date'], now: Date.now() });
    mock.timers.tick(40000);
    await assert.rejects(() => runtime.run((call) => mapping.map(call, proof)), {
      code: 'EK_EID_FEDERATION',
    });
    mock.timers.reset();
    authorityMode = 'wait';
    const work = runtime.run((call) => mapping.map(call, proof), { timeoutMs: 100 }),
      rejected = assert.rejects(work, { code: 'EK_TIMEOUT' });
    await began;
    await rejected;
    assert.equal(runtime.stats().active, 1);
    release();
    authorityMode = 'close-auth';
    await assert.rejects(() => runtime.run((call) => mapping.map(call, proof)), {
      code: 'EK_EID_FEDERATION',
    });
    authorityMode = 'allow';
    await auth.close();
    await assert.rejects(() => runtime.run((call) => mapping.map(call, proof)), {
      code: 'EK_EID_FEDERATION',
    });
  } finally {
    mock.timers.reset();
    release();
    await auth.close();
    await other.close();
  }
}
