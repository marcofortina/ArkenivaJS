import assert from 'node:assert/strict';
import { test } from 'node:test';
import { jwtVerify, importJWK } from 'jose';
import { createIssuer } from '../http-issuer.mjs';

test('The owned loopback issuer provides verifiable synthetic credentials without token output', async () => {
  const issuer = await createIssuer();
  try {
    const discovery = await (
      await globalThis.fetch(issuer.origin + '/.well-known/openid-configuration')
    ).json();
    assert.equal(discovery.issuer, issuer.origin);
    const keys = await (await globalThis.fetch(discovery.jwks_uri)).json();
    const key = await importJWK(keys.keys[0], 'RS256');
    const verified = await jwtVerify(await issuer.token(), key, {
      issuer: issuer.origin,
      audience: issuer.audience,
    });
    assert.equal(verified.payload.tenant_id, 'synthetic-tenant');
    await assert.rejects(
      jwtVerify(await issuer.token({ audience: 'api://other' }), key, {
        audience: issuer.audience,
      }),
    );
    assert.equal((await globalThis.fetch(issuer.origin + '/unknown')).status, 404);
  } finally {
    await issuer.close();
    await issuer.close();
  }
});
