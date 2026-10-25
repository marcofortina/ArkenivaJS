// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';
import { createWebAuthnService } from '@arkenivajs/security-webauthn';
import type { WebAuthnCeremony } from '@arkenivajs/security-webauthn';
import { KitError } from '@arkenivajs/core';
import { connectBrowser } from './cdp.js';
import { webAuthnServiceFixture } from '../integration/webauthn-service-fixture.js';
import { startMfaWorker } from '../integration/mfa-worker.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;

// The private parent pipe transfers an already authenticated fixture principal; no HTTP input enters this authority.
const finishWorker = `
import {createApplication,KitError} from '@arkenivajs/core';
import {postgresPlugin} from '@arkenivajs/database-postgres';
import {createWebAuthnService} from '@arkenivajs/security-webauthn';
import {createPostgresWebAuthnStateStore} from './dist/webauthn-state-store.js';
import {createPostgresMfaEvidenceStore} from './dist/mfa-evidence-store.js';
import {createPostgresMfaRateLimitStore} from './dist/mfa-rate-limit-store.js';
import {setTimeout} from 'node:timers/promises';
const c=JSON.parse(process.argv[1]);
const freeze=value=>{if(value&&typeof value==='object'){for(const field of Object.values(value))freeze(field);Object.freeze(value);}return value;};
const owner=freeze(c.owner), approved=new WeakSet([owner]);
const app=await createApplication({service:{name:'webauthn-service-worker',version:'1.0.0',environment:'test'},plugins:[postgresPlugin()],databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:2}}});
try {
  await app.start();
  const durable=createPostgresWebAuthnStateStore(app.sql,'main',c.schema,()=>c.now);
  const state={...durable,async advanceCounter(input,options){
    await app.sql.execute('main',{text:'INSERT INTO '+c.schema+'.webauthn_barrier (id,version,previous) VALUES (:id,:version,:previous)',bindings:{id:c.index,version:input.expectedVersion,previous:input.previousCounter}});
    let released=false;
    for(let attempt=0;attempt<250;attempt++){
      const row=await app.sql.queryOne('main',{text:'SELECT bool_and(released) AS released FROM '+c.schema+'.webauthn_barrier'});
      if(row?.released===true){released=true;break;}await setTimeout(20);
    }
    if(!released)throw new Error('Owned CAS barrier timed out');
    return durable.advanceCounter(input,options);
  }};
  const service=createWebAuthnService({rpId:c.rp, rpName:'Disposable application',expectedOrigins:[c.origin],environment:'test',clock:{nowEpochMs:()=>c.now},stateStore:state,rateLimitStore:createPostgresMfaRateLimitStore(app.sql,'main',c.schema),evidenceStore:createPostgresMfaEvidenceStore(app.sql,'main',c.schema),subjectAuthority:{usage:'test-only',async resolveSubject(value){if(!approved.has(value))throw new KitError({code:'EK_AUTH_FORBIDDEN',message:'Unowned fixture principal'});return value;},async authorize({subject,action}){if(!approved.has(subject)||action!=='finish-authentication')throw new KitError({code:'EK_AUTH_FORBIDDEN',message:'Fixture action denied'});},async resolvePasswordlessSubject(){throw new KitError({code:'EK_AUTH_FORBIDDEN',message:'Fixture action denied'});}}});
  const input=new Promise(resolve=>{let text='';process.stdin.on('data',chunk=>{text+=String(chunk);if(text.length>8192)throw new Error('Worker input exceeds its bound');});process.stdin.once('end',()=>resolve(JSON.parse(text)));});
  console.log(JSON.stringify({ready:true}));const payload=await input;
  try{await service.finishAuthentication(owner,payload.ceremonyId,payload.response);console.log(JSON.stringify({result:'OK'}));}
  catch(error){if(error instanceof KitError&&error.code==='EK_MFA_CREDENTIAL_CONFLICT')console.log(JSON.stringify({result:error.code}));else throw error;}
}catch(error){console.error(JSON.stringify(error instanceof KitError?error.toSafeJSON():{code:'EK_INTERNAL'}));process.exitCode=1;}
finally{await app.stop();process.stdin.destroy();}
`;

test(
  'The pinned browser client and a virtual CTAP2 authenticator complete the public service with durable SQL',
  { timeout: 60000 },
  async (t) => {
    assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
    assert.equal(process.env.ARKENIVA_WEBAUTHN_BROWSER_DISPOSABLE, '1');
    const endpoint = process.env.ARKENIVA_WEBAUTHN_BROWSER_URL;
    assert.ok(endpoint, 'An explicit disposable browser endpoint is required');
    const origin = new URL(
      process.env.ARKENIVA_WEBAUTHN_BROWSER_ORIGIN ?? 'http://localhost:19377',
    );
    assert.equal(origin.protocol, 'http:');
    assert.equal(origin.hostname, 'localhost');
    assert.equal(origin.pathname, '/');
    assert.equal(origin.search + origin.hash + origin.username + origin.password, '');
    assert.ok(Number(origin.port) >= 1024);
    const client = await readFile(
      new URL('../dist/bundle/index.umd.min.js', import.meta.resolve('@simplewebauthn/browser')),
    );
    const server = createServer((request, response) => {
      response.setHeader('cache-control', 'no-store');
      response.setHeader('x-content-type-options', 'nosniff');
      response.setHeader(
        'content-security-policy',
        "default-src 'none'; script-src 'self'; frame-ancestors 'none'",
      );
      if (request.method !== 'GET' || !['/', '/client.js'].includes(request.url ?? '')) {
        response.writeHead(404).end();
        return;
      }
      response.setHeader(
        'content-type',
        request.url === '/client.js' ? 'text/javascript' : 'text/html',
      );
      response.end(
        request.url === '/client.js'
          ? client
          : '<!doctype html><title>Disposable WebAuthn test</title><script src="/client.js" defer></script>',
      );
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(Number(origin.port), '127.0.0.1', resolve);
    });
    let browser: Awaited<ReturnType<typeof connectBrowser>> | undefined;
    let fixture: Awaited<ReturnType<typeof webAuthnServiceFixture>> | undefined;
    try {
      browser = await connectBrowser(endpoint);
      fixture = await webAuthnServiceFixture(origin.origin);
      const f = fixture,
        page = browser;
      await page.command('Page.enable');
      await page.command('WebAuthn.enable', { enableUI: false });
      const authenticator = await page.command('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      await page.command('Page.navigate', { url: origin.origin });
      let loaded = false;
      for (let attempt = 0; attempt < 20; attempt++) {
        try {
          loaded = (await page.evaluate('typeof SimpleWebAuthnBrowser === "object"')) === true;
        } catch {
          /* Navigation may replace the initial execution context. */
        }
        if (loaded) break;
        await setTimeout(50);
      }
      assert.ok(loaded, 'The pinned browser SDK must load from the owned frontend');
      const response = (ceremony: WebAuthnCeremony, registration = false) =>
        page.evaluate(
          'SimpleWebAuthnBrowser.' +
            (registration ? 'startRegistration' : 'startAuthentication') +
            '(' +
            JSON.stringify({ optionsJSON: ceremony.optionsJSON }) +
            ')',
        );
      const owner = await f.subject({ acr: 'urn:fixture:reauthenticated' });
      await assert.rejects(f.service.beginRegistration(owner), hasCode('EK_AUTH_FORBIDDEN'));
      f.approveEnrollment(owner);
      await assert.rejects(
        f.service.beginRegistration(Object.freeze({ ...owner })),
        hasCode('EK_AUTH_FORBIDDEN'),
      );
      const registration = await f.service.beginRegistration(owner);
      const registered = await f.service.finishRegistration(
        owner,
        registration.ceremonyId,
        await response(registration, true),
      );
      const stored = await f.state.getCredential(registered.credentialId, f.settings.rpId);
      assert.ok(stored);
      assert.equal(typeof authenticator.authenticatorId, 'string');
      assert.equal(Buffer.from(stored.userHandle, 'base64url').length, 32);
      assert.equal((await f.service.listCredentials(owner)).length, 1);
      await assert.rejects(
        f.service.finishRegistration(owner, registration.ceremonyId, {}),
        hasCode('EK_MFA_CHALLENGE_EXPIRED'),
      );

      const ceremony = await f.service.beginAuthentication(owner),
        signed = await response(ceremony);
      const foreign = await f.subject({ tenant_id: 'foreign-tenant' });
      await assert.rejects(
        f.service.finishAuthentication(foreign, ceremony.ceremonyId, signed),
        hasCode('EK_MFA_CHALLENGE_EXPIRED'),
      );
      const proof = await f.service.finishAuthentication(owner, ceremony.ceremonyId, signed);
      assert.equal(proof.assurance, 'phishing-resistant');
      const advanced = (await f.state.getCredential(registered.credentialId, f.settings.rpId))!;
      assert.ok(advanced.counter > stored.counter);
      assert.notEqual(advanced.stateVersion, stored.stateVersion);
      const evidenceBinding = {
        evidenceId: proof.evidenceId,
        issuer: owner.issuer,
        subject: owner.subject,
        ...(owner.tenant ? { tenantId: owner.tenant.tenantId } : {}),
        primarySessionId: owner.primarySessionId,
        now: new Date(f.clock()).toISOString(),
      };
      assert.ok(await f.evidence.consume(evidenceBinding));
      assert.equal(await f.evidence.consume(evidenceBinding), null);
      await assert.rejects(
        f.service.finishAuthentication(owner, ceremony.ceremonyId, signed),
        hasCode('EK_MFA_CHALLENGE_EXPIRED'),
      );

      await page.command('WebAuthn.setCredentialProperties', {
        authenticatorId: authenticator.authenticatorId,
        credentialId: Buffer.from(registered.credentialId, 'base64url').toString('base64'),
        signCount: -1,
      });
      const regression = await f.service.beginAuthentication(owner);
      await assert.rejects(
        f.service.finishAuthentication(owner, regression.ceremonyId, await response(regression)),
        hasCode('EK_MFA_COUNTER_REGRESSION'),
      );
      assert.equal(
        (await f.state.getCredential(registered.credentialId, f.settings.rpId))!.counter,
        advanced.counter,
      );
      // Bootstrap owned test state for a counterless device after proving production policy rejects the drop.
      await f.app.sql.execute('main', {
        text: `UPDATE ${f.schema}.mfa_webauthn_credentials SET counter=0,state_version=gen_random_uuid() WHERE credential_id=:id`,
        bindings: { id: registered.credentialId },
      });
      f.setTime(f.clock() + 60000);
      // Distinct, genuinely signed counterless assertions reach one stale version from two service processes.
      await f.app.sql.execute('main', {
        text: `CREATE TABLE ${f.schema}.webauthn_barrier (id INTEGER PRIMARY KEY,version TEXT NOT NULL,previous BIGINT NOT NULL,released BOOLEAN NOT NULL DEFAULT FALSE)`,
      });
      const attempts = await Promise.all([
        f.service.beginAuthentication(owner),
        f.service.beginAuthentication(owner),
      ]);
      const responses = [await response(attempts[0]!), await response(attempts[1]!)];
      const workers = attempts.map((_, index) =>
        startMfaWorker(t, finishWorker, {
          schema: f.schema,
          now: f.clock(),
          owner,
          rp: f.settings.rpId,
          origin: origin.origin,
          index,
        }),
      );
      await Promise.all(workers.map((worker) => worker.ready));
      workers.forEach((worker, index) =>
        worker.go({ ceremonyId: attempts[index]!.ceremonyId, response: responses[index] }),
      );
      try {
        let arrived = false;
        for (let attempt = 0; attempt < 250; attempt++) {
          const row = await f.app.sql.queryOne<{
            count: string;
            versions: string;
            previous: string;
          }>('main', {
            text: `SELECT count(*)::text AS count,count(DISTINCT version)::text AS versions,max(previous)::text AS previous FROM ${f.schema}.webauthn_barrier`,
          });
          if (row?.count === '2') {
            assert.equal(row.versions, '1');
            assert.equal(row.previous, '0');
            arrived = true;
            break;
          }
          await setTimeout(20);
        }
        assert.ok(arrived, 'Both signed assertions must reach the durable CAS barrier');
      } finally {
        await f.app.sql.execute('main', {
          text: `UPDATE ${f.schema}.webauthn_barrier SET released=TRUE`,
        });
      }
      assert.deepEqual((await Promise.all(workers.map((worker) => worker.result))).sort(), [
        'EK_MFA_CREDENTIAL_CONFLICT',
        'OK',
      ]);
      assert.equal(
        (await f.state.getCredential(registered.credentialId, f.settings.rpId))!.counter,
        0,
      );
      f.setTime(f.clock() + 60000);

      // A verified credential maps to the application account without requiring a primary session.
      f.revokeSession(owner);
      await assert.rejects(f.service.listCredentials(owner), hasCode('EK_AUTH_FORBIDDEN'));
      const discoverable = await f.service.beginPasswordless();
      const passwordless = await f.service.finishPasswordless(
        discoverable.ceremonyId,
        await response(discoverable),
      );
      assert.equal(passwordless.subject, owner.subject);
      assert.equal(passwordless.tenantId, owner.tenant?.tenantId);
      assert.equal('sessionToken' in passwordless, false);
      const handoff = {
        ...evidenceBinding,
        evidenceId: passwordless.evidence.evidenceId,
        primarySessionId: discoverable.ceremonyId,
        now: new Date(f.clock()).toISOString(),
      };
      assert.ok(await f.evidence.consume(handoff));
      assert.equal(await f.evidence.consume(handoff), null);

      const current = await f.subject({ sid: 'new-session', acr: 'urn:fixture:reauthenticated' });
      // A committed evidence write with an unknown outcome must not return success or permit replay.
      const uncertain = createWebAuthnService({
        ...f.settings,
        evidenceStore: {
          ...f.settings.evidenceStore,
          async recordOnce(value, options) {
            await f.evidence.recordOnce(value, options);
            throw new Error('Synthetic ambiguous evidence acknowledgement');
          },
        },
      });
      const pending = await uncertain.beginAuthentication(current),
        failedProof = await response(pending);
      await assert.rejects(
        uncertain.finishAuthentication(current, pending.ceremonyId, failedProof),
        hasCode('EK_MFA_STORAGE'),
      );
      await assert.rejects(
        f.service.finishAuthentication(current, pending.ceremonyId, failedProof),
        hasCode('EK_MFA_CHALLENGE_EXPIRED'),
      );

      for (const bits of [{ isBadUV: true }, { isBadUP: true }, { isBogusSignature: true }]) {
        const previous = (await f.state.getCredential(registered.credentialId, f.settings.rpId))!
          .stateVersion;
        await page.command('WebAuthn.setResponseOverrideBits', {
          authenticatorId: authenticator.authenticatorId,
          ...bits,
        });
        try {
          const invalid = await f.service.beginAuthentication(current);
          await assert.rejects(
            f.service.finishAuthentication(current, invalid.ceremonyId, await response(invalid)),
            hasCode('EK_MFA_INVALID'),
          );
          assert.equal(
            (await f.state.getCredential(registered.credentialId, f.settings.rpId))!.stateVersion,
            previous,
          );
        } finally {
          await page.command('WebAuthn.setResponseOverrideBits', {
            authenticatorId: authenticator.authenticatorId,
          });
        }
      }

      f.setTime(f.clock() + 60000);
      const management = await f.service.beginAuthentication(current);
      const factor = await f.service.finishAuthentication(
        current,
        management.ceremonyId,
        await response(management),
      );
      const grant = await f.management(current, factor.evidenceId);
      await assert.rejects(
        f.service.revokeCredential(current, registered.credentialId, Object.freeze({ ...grant })),
        hasCode('EK_AUTH_FORBIDDEN'),
      );
      const outstanding = await f.service.beginAuthentication(current);
      const outstandingProof = await response(outstanding);
      await f.service.revokeCredential(current, registered.credentialId, grant);
      assert.equal((await f.service.listCredentials(current)).length, 0);
      await assert.rejects(
        f.service.finishAuthentication(current, outstanding.ceremonyId, outstandingProof),
        hasCode('EK_MFA_CHALLENGE_EXPIRED'),
      );
      await assert.rejects(
        f.service.revokeCredential(current, registered.credentialId, grant),
        hasCode('EK_AUTH_FORBIDDEN'),
      );
      const anonymous = await f.service.beginPasswordless();
      await assert.rejects(
        f.service.finishPasswordless(anonymous.ceremonyId, await response(anonymous)),
        hasCode('EK_MFA_INVALID'),
      );
    } finally {
      try {
        await browser?.close();
      } finally {
        try {
          await fixture?.close();
        } finally {
          server.closeAllConnections();
          await new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve())),
          );
        }
      }
    }
  },
);
