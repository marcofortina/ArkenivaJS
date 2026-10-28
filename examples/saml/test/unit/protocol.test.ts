// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:https';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes, createVerify } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { getVerifiedXml } from '@node-saml/node-saml/lib/xml.js';
import { createSamlService } from '@arkenivajs/security-saml';
import type { SamlService } from '@arkenivajs/security-saml';
import { DOMParser } from '@xmldom/xmldom';
import { browserTransfer } from '../../dist/browser-transfer.js';
const parse = (xml: string): Document =>
  new DOMParser().parseFromString(xml, 'text/xml') as unknown as Document;
const NS = { protocol: 'urn:oasis:names:tc:SAML:2.0:protocol' };
import { fixture } from '../fixture.js';

for (const binding of ['redirect', 'post'] as const)
  test(
    `Public installed SAML HTTPS ${binding} browser-transfer endpoints validate SP signatures and bind ACS to an owned browser transaction`,
    { timeout: 15000 },
    async () => {
      const f = await fixture(binding),
        spCertificate = await readFile(join(f.directory, 'sp.pem')),
        idpCertificate = await readFile(join(f.directory, 'idp.pem'));
      let spOrigin = '',
        idpOrigin = '',
        saml: SamlService;
      const transactions = new Map<string, string>();
      const sp = createServer(
        { key: await readFile(join(f.directory, 'sp.key')), cert: spCertificate },
        (incoming, outgoing) => {
          void (async () => {
            if (incoming.url === '/begin') {
              const login = await saml.beginLogin({ returnPath: '/app' }),
                cookie = randomBytes(32).toString('base64url');
              transactions.set(cookie, login.requestId);
              outgoing.setHeader(
                'set-cookie',
                '__Host-saml-flow=' + cookie + '; Path=/; Secure; HttpOnly; SameSite=None',
              );
              const transfer = browserTransfer(login);
              outgoing.writeHead(transfer.status, transfer.headers);
              outgoing.end(transfer.body);
              return;
            }
            if (incoming.url !== '/acs' || incoming.method !== 'POST') {
              outgoing.writeHead(404).end();
              return;
            }
            const chunks: Buffer[] = [];
            let size = 0;
            for await (const chunk of incoming) {
              size += (chunk as Buffer).length;
              if (size > 400000) throw new Error('The owned ACS body is oversized');
              chunks.push(Buffer.from(chunk));
            }
            const values = new URLSearchParams(Buffer.concat(chunks).toString('utf8')),
              cookie = /^__Host-saml-flow=([A-Za-z0-9_-]{43})$/.exec(
                incoming.headers.cookie ?? '',
              )?.[1],
              expected = cookie ? transactions.get(cookie) : undefined;
            if (
              !expected ||
              values.get('RelayState') !== expected ||
              values.getAll('SAMLResponse').length !== 1 ||
              values.getAll('RelayState').length !== 1
            ) {
              outgoing.writeHead(403).end();
              return;
            }
            transactions.delete(cookie!);
            const identity = await saml.consumeResponse(
              { inResponseTo: expected, relayState: expected },
              values.get('SAMLResponse')!,
            );
            outgoing.setHeader('content-type', 'application/json');
            outgoing.end(
              JSON.stringify({
                accepted: identity.subject === 'synthetic-account',
                assurance: identity.assurance,
                tenantClaimGranted: Object.hasOwn(identity.claims, 'tenant_id'),
              }),
            );
          })().catch(() => {
            outgoing.writeHead(400).end('The owned SAML callback was rejected');
          });
        },
      );
      const idp = createServer(
        { key: await readFile(join(f.directory, 'idp.key')), cert: idpCertificate },
        (incoming, outgoing) => {
          void (async () => {
            let encoded: string, relay: string;
            if (binding === 'redirect') {
              assert.equal(incoming.method, 'GET');
              const url = new URL(incoming.url!, idpOrigin),
                values = url.searchParams;
              const signed = ['SAMLRequest', 'RelayState', 'SigAlg']
                .map((name) =>
                  url.search
                    .slice(1)
                    .split('&')
                    .find((part) => part.startsWith(name + '='))!,
                )
                .join('&');
              assert.equal(
                values.get('SigAlg'),
                'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
              );
              assert.equal(
                createVerify('RSA-SHA256')
                  .update(signed)
                  .verify(spCertificate, Buffer.from(values.get('Signature')!, 'base64')),
                true,
              );
              encoded = inflateRawSync(Buffer.from(values.get('SAMLRequest')!, 'base64'), {
                maxOutputLength: 262144,
              }).toString('utf8');
              relay = values.get('RelayState')!;
            } else {
              assert.equal(incoming.method, 'POST');
              const chunks: Buffer[] = [];
              for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
              const values = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
              encoded = Buffer.from(values.get('SAMLRequest')!, 'base64').toString('utf8');
              relay = values.get('RelayState')!;
              assert.ok(
                getVerifiedXml(encoded, parse(encoded).documentElement, [
                  spCertificate.toString('utf8'),
                ]),
              );
            }
            const root = parse(encoded).documentElement;
            assert.equal(root.localName, 'AuthnRequest');
            assert.equal(root.namespaceURI, NS.protocol);
            assert.equal(root.getAttribute('AssertionConsumerServiceURL'), spOrigin + '/acs');
            assert.equal(root.getAttribute('ID'), relay);
            const response = f.response(relay, {
              issuer: idpOrigin + '/entity',
              destination: spOrigin + '/acs',
              audience: spOrigin + '/entity',
            });
            outgoing.setHeader('content-type', 'application/json');
            outgoing.end(JSON.stringify({ SAMLResponse: response, RelayState: relay }));
          })().catch(() => {
            outgoing.writeHead(400).end('The owned IdP rejected the request');
          });
        },
      );
      const listen = async (server: typeof sp) => {
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
        const address = server.address();
        assert.ok(address && typeof address === 'object');
        return 'https://127.0.0.1:' + address.port;
      };
      const exchange = (url: string, ca: Buffer, method = 'GET', body?: string, cookie?: string) =>
        new Promise<{ status: number; body: string; location?: string; cookie?: string }>(
          (resolve, reject) => {
            const outgoing = request(
              url,
              {
                method,
                ca,
                rejectUnauthorized: true,
                agent: false,
                headers: {
                  ...(body === undefined
                    ? {}
                    : { 'content-type': 'application/x-www-form-urlencoded' }),
                  ...(cookie === undefined ? {} : { cookie }),
                },
              },
              (incoming) => {
                const chunks: Buffer[] = [];
                incoming.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
                incoming.once('error', reject);
                incoming.once('end', () =>
                  resolve({
                    status: incoming.statusCode!,
                    ...(incoming.headers.location ? { location: incoming.headers.location } : {}),
                    body: Buffer.concat(chunks).toString('utf8'),
                    ...(incoming.headers['set-cookie']?.[0]
                      ? { cookie: incoming.headers['set-cookie'][0].split(';')[0]! }
                      : {}),
                  }),
                );
              },
            );
            outgoing.once('error', reject);
            outgoing.end(body);
          },
        );
      try {
        spOrigin = await listen(sp);
        idpOrigin = await listen(idp);
        saml = createSamlService({
          ...f.settings,
          entityId: spOrigin + '/entity',
          expectedAudience: spOrigin + '/entity',
          acsUrl: spOrigin + '/acs',
          trustedIdpMetadata: f.settings.trustedIdpMetadata.replaceAll(
            'https://idp.fixture.invalid',
            idpOrigin,
          ),
        });
        const initial = await exchange(spOrigin + '/begin', spCertificate);
        assert.ok(initial.cookie);
        let upstream: Awaited<ReturnType<typeof exchange>>;
        if (binding === 'redirect') {
          assert.equal(initial.status, 303);
          assert.ok(initial.location);
          upstream = await exchange(initial.location, idpCertificate);
        } else {
          assert.equal(initial.status, 200);
          const page = parse(initial.body.slice('<!doctype html>'.length)),
            form = page.getElementsByTagName('form')[0]!;
          assert.equal(form.getAttribute('method'), 'post');
          const values = new URLSearchParams();
          for (const input of Array.from(form.getElementsByTagName('input')))
            values.append(input.getAttribute('name')!, input.getAttribute('value')!);
          upstream = await exchange(
            form.getAttribute('action')!,
            idpCertificate,
            'POST',
            values.toString(),
          );
        }
        assert.equal(upstream.status, 200, upstream.body);
        const form = new URLSearchParams(
          JSON.parse(upstream.body) as Record<string, string>,
        ).toString();
        assert.equal(
          (
            await exchange(
              spOrigin + '/acs',
              spCertificate,
              'POST',
              form,
              '__Host-saml-flow=' + randomBytes(32).toString('base64url'),
            )
          ).status,
          403,
        );
        const accepted = await exchange(
          spOrigin + '/acs',
          spCertificate,
          'POST',
          form,
          initial.cookie,
        );
        assert.equal(accepted.status, 200, accepted.body);
        assert.deepEqual(JSON.parse(accepted.body), {
          accepted: true,
          assurance: 'single-factor',
          tenantClaimGranted: false,
        });
        assert.equal(
          (await exchange(spOrigin + '/acs', spCertificate, 'POST', form, initial.cookie)).status,
          403,
        );
      } finally {
        sp.closeAllConnections();
        idp.closeAllConnections();
        await Promise.all(
          [sp, idp].map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
        );
        await f.close();
      }
    },
  );
