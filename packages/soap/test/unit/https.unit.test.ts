// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:https';
import { TLSSocket } from 'node:tls';
import { setInterval, clearInterval } from 'node:timers';
import { setTimeout as delay } from 'node:timers/promises';
import { Client, listen } from 'soap';
import type { IHttpClient } from 'soap';
import { KitError, createApplication } from '@arkenivajs/core';
import { soapPlugin, SOAP_CAPABILITY } from '../../dist/index.js';
import type { SoapService } from '../../dist/index.js';
import { HttpsConnection } from '../../dist/https.js';
import type { WireProfile } from '../../dist/https.js';
import { nativeWsdl } from '../../dist/backend.js';
import { NativeParser } from '../../dist/parser.js';
import { contract, response } from '../fixture.js';

const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
const headers = {
  'Content-Type': 'text/xml; charset=utf-8',
  SOAPAction: '"urn:arkenivajs:ReadStock"',
};
test(
  'Real fixed HTTPS transport validates trust, SOAP versions, bounds, cancellation and native client identity',
  { timeout: 30000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-soap-tls-'));
    await chmod(directory, 0o700);
    t.after(() => rm(directory, { recursive: true, force: true }));
    const keyPath = join(directory, 'private.pem'),
      certPath = join(directory, 'certificate.pem');
    await promisify(execFile)(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-sha256',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        keyPath,
        '-out',
        certPath,
      ],
      { timeout: 10000 },
    );
    await chmod(keyPath, 0o600);
    const key = await readFile(keyPath),
      ca = await readFile(certPath);
    let received = 0,
      disconnected = 0,
      nativeCalls = 0;
    let held: (() => void) | undefined, heldClosed: (() => void) | undefined;
    const server = createServer({ key, cert: ca, minVersion: 'TLSv1.2' }, (request, reply) => {
      request.resume();
      request.once('end', () => {
        received++;
        reply.setHeader(
          'Content-Type',
          request.url === '/v12' ? 'application/soap+xml' : 'text/xml',
        );
        reply.on('close', () => {
          disconnected++;
        });
        if (request.url === '/redirect') {
          reply.writeHead(302, { Location: '/ok' });
          reply.end();
        } else if (request.url === '/large') reply.end('x'.repeat(8192));
        else if (request.url === '/json') {
          reply.setHeader('Content-Type', 'application/json');
          reply.end('{"private":"response"}');
        } else if (request.url === '/drip') {
          reply.write(' ');
          const timer = setInterval(() => reply.write(' '), 10);
          reply.once('close', () => clearInterval(timer));
        } else if (request.url === '/hold') {
          const notify = heldClosed;
          reply.once('close', () => notify?.());
          held?.();
          /* Remain open until cancellation closes the owned request. */
        } else if (request.url === '/v12')
          reply.end(
            response.replaceAll(
              'http://schemas.xmlsoap.org/soap/envelope/',
              'http://www.w3.org/2003/05/soap-envelope',
            ),
          );
        else reply.end(response);
      });
    });
    server.on('tlsClientError', () => undefined);
    const nativeServer = listen(
      server,
      '/native',
      {
        InventoryService: {
          InventoryPort: {
            ReadStock(value: { sku: string }) {
              assert.equal(typeof value.sku, 'string');
              assert.ok(value.sku.startsWith('000'));
              nativeCalls++;
              return { quantity: 12 };
            },
          },
        },
      },
      contract,
    );
    void nativeServer;
    const rpcContract = contract
      .replace('style="document"', 'style="rpc"')
      .replace(
        '<part name="parameters" element="tns:ReadStock"/>',
        '<part name="sku" type="xs:string"/>',
      )
      .replace(
        '<part name="parameters" element="tns:ReadStockResponse"/>',
        '<part name="quantity" type="xs:int"/>',
      );
    const twelveContract = contract.replace(
      'http://schemas.xmlsoap.org/wsdl/soap/',
      'http://schemas.xmlsoap.org/wsdl/soap12/',
    );
    listen(
      server,
      '/rpc',
      {
        InventoryService: {
          InventoryPort: {
            ReadStock() {
              return { quantity: 13 };
            },
          },
        },
      },
      rpcContract,
    );
    listen(server, {
      path: '/native12',
      services: {
        InventoryService: {
          InventoryPort: {
            ReadStock() {
              return { quantity: 14 };
            },
          },
        },
      },
      xml: twelveContract,
      forceSoap12Headers: true,
    });
    let authenticationMode: 'basic' | 'bearer' | 'wsse' = 'basic',
      authenticationValue = randomUUID(),
      authenticatedCalls = 0;
    const nonces = new Set<string>();
    const authenticated = listen(
      server,
      '/authenticated',
      {
        InventoryService: {
          InventoryPort: {
            ReadStock() {
              authenticatedCalls++;
              return { quantity: 15 };
            },
          },
        },
      },
      contract,
    );
    const scalar = (value: unknown): string => {
      if (typeof value === 'string') return value;
      if (value && typeof value === 'object') {
        const text = Object.getOwnPropertyDescriptor(value, '$value')?.value;
        if (typeof text === 'string') return text;
      }
      return '';
    };
    authenticated.authenticate = (security: unknown, _callback, request) => {
      if (authenticationMode === 'basic')
        return (
          request?.headers.authorization ===
          'Basic ' + Buffer.from('fixture-user:' + authenticationValue).toString('base64')
        );
      if (authenticationMode === 'bearer')
        return request?.headers.authorization === 'Bearer ' + authenticationValue;
      if (!security || typeof security !== 'object') return false;
      const token: unknown = Object.getOwnPropertyDescriptor(security, 'UsernameToken')?.value;
      if (!token || typeof token !== 'object') return false;
      const field = (name: string) => scalar(Object.getOwnPropertyDescriptor(token, name)?.value);
      const username = field('Username'),
        nonce = field('Nonce'),
        created = field('Created'),
        password = field('Password');
      if (
        username !== 'fixture-user' ||
        !nonce ||
        !created ||
        !password ||
        nonces.has(nonce) ||
        Math.abs(Date.now() - Date.parse(created)) > 60000
      )
        return false;
      const expected = createHash('sha1')
          .update(
            Buffer.concat([
              Buffer.from(nonce, 'base64'),
              Buffer.from(created),
              Buffer.from(authenticationValue),
            ]),
          )
          .digest(),
        actual = Buffer.from(password, 'base64');
      const accepted = expected.length === actual.length && timingSafeEqual(expected, actual);
      if (accepted) nonces.add(nonce);
      return accepted;
    };
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const profile = (path: string): WireProfile => ({
      endpoint: 'https://127.0.0.1:' + address.port + path,
      protocol: '1.1',
      timeoutMs: 2000,
      maxConcurrent: 1,
      maxInputBytes: 1048576,
      maxResponseBytes: 4096,
    });
    const connection = await HttpsConnection.create(profile('/ok'), new AbortController().signal);
    try {
      await t.test('Only a verified configured CA permits the actual TLS request', async () => {
        await assert.rejects(
          connection.request(response, headers, {}),
          code('EK_BACKEND_UNAVAILABLE'),
        );
        assert.equal(received, 0);
        const result = await connection.request(response, headers, { ca });
        assert.equal(result.response.status, 200);
        assert.equal(result.body, response);
        assert.equal(received, 1);
      });
      await t.test(
        'Native address selection uses only startup-captured answers for the configured DNS name',
        async () => {
          const named = await HttpsConnection.create(
            { ...profile('/ok'), endpoint: 'https://localhost:' + address.port + '/ok' },
            new AbortController().signal,
          );
          try {
            assert.equal((await named.request(response, headers, { ca })).body, response);
          } finally {
            await named.close();
          }
        },
      );
      await t.test(
        'The actual approved native client uses the bounded worker and the real HTTPS response',
        async () => {
          const wsdl = await nativeWsdl(contract),
            parser = await NativeParser.create(
              { source: contract, protocol: '1.1', timeoutMs: 10000, maxBytes: 4096 },
              new AbortController().signal,
            );
          try {
            Object.defineProperty(wsdl, 'xmlToObject', {
              value: (source: string) => parser.parse(source),
              writable: false,
              configurable: false,
            });
            const transport: IHttpClient = {
              request(_url, body: string, callback) {
                const pending = connection.request(body, headers, { ca }).then(
                  (result) => {
                    callback(null, result.response, result.body);
                    return result.response;
                  },
                  (error: unknown) => {
                    callback(error);
                    throw error;
                  },
                );
                void pending.catch(() => undefined);
                return pending;
              },
            };
            const client = new Client(wsdl, connection.profile.endpoint, { httpClient: transport });
            assert.ok(client instanceof Client);
            const [value] = (await client.ReadStockAsync({ sku: '0007' })) as [
              { quantity: number },
            ];
            assert.equal(value.quantity, 12);
          } finally {
            await parser.close();
          }
        },
      );
      await t.test(
        'Invalid durations, headers, envelopes and an already aborted signal make no request',
        async () => {
          const before = received;
          for (const timeoutMs of [0, -1, 0.1, NaN, Infinity, 2001])
            await assert.rejects(
              connection.request(response, headers, { ca }, { timeoutMs }),
              code('EK_CONFIG_INVALID'),
            );
          await assert.rejects(
            connection.request(response, { Authorization: 'untrusted' }, { ca }),
            code('EK_CONFIG_INVALID'),
          );
          await assert.rejects(
            connection.request('{"private":"body"}', headers, { ca }),
            code('EK_SOAP_SCHEMA'),
          );
          await assert.rejects(
            connection.request(response, headers, { ca }, { signal: AbortSignal.abort() }),
            code('EK_ABORTED'),
          );
          assert.equal(received, before);
        },
      );
      await t.test(
        'Redirects, oversized bodies and JSON content are rejected without a second request',
        async () => {
          for (const path of ['/redirect', '/large', '/json']) {
            const limited = await HttpsConnection.create(
              profile(path),
              new AbortController().signal,
            );
            const before = received;
            try {
              await assert.rejects(limited.request(response, headers, { ca }));
            } finally {
              await limited.close();
            }
            assert.equal(received, before + 1);
          }
        },
      );
      await t.test(
        'A total deadline terminates even a continuously active slow response',
        async () => {
          const drip = await HttpsConnection.create(profile('/drip'), new AbortController().signal);
          try {
            await assert.rejects(
              drip.request(response, headers, { ca }, { timeoutMs: 100 }),
              code('EK_TIMEOUT'),
            );
          } finally {
            await drip.close();
          }
          assert.ok(disconnected > 0);
        },
      );
      await t.test(
        'Caller cancellation, physical reservations and lifecycle close cancel real native sockets',
        async () => {
          const hold = await HttpsConnection.create(profile('/hold'), new AbortController().signal);
          const controller = new AbortController();
          const pending = hold.request(response, headers, { ca }, { signal: controller.signal });
          const denied = assert.rejects(pending, code('EK_ABORTED'));
          await assert.rejects(
            hold.request(response, headers, { ca }),
            code('EK_BACKEND_UNAVAILABLE'),
          );
          controller.abort();
          await denied;
          const active = hold.request(response, headers, { ca });
          const stopped = assert.rejects(active, code('EK_ABORTED'));
          await delay(10);
          const closing = hold.close();
          assert.equal(hold.close(), closing);
          await closing;
          await stopped;
          await assert.rejects(hold.request(response, headers, { ca }), code('EK_RESOURCE_CLOSED'));
        },
      );
      await t.test('Declared SOAP 1.2 requests retain their actual wire version', async () => {
        const twelve = await HttpsConnection.create(
          { ...profile('/v12'), protocol: '1.2' },
          new AbortController().signal,
        );
        try {
          const result = await twelve.request(
            response.replaceAll(
              'http://schemas.xmlsoap.org/soap/envelope/',
              'http://www.w3.org/2003/05/soap-envelope',
            ),
            { 'Content-Type': 'application/soap+xml; charset=utf-8' },
            { ca },
          );
          assert.ok(result.body.includes('http://www.w3.org/2003/05/soap-envelope'));
        } finally {
          await twelve.close();
        }
      });
      await t.test(
        'Public cancellation destroys an actually held upstream request while saturation performs no second call',
        async () => {
          const wsdlFile = join(directory, 'held.wsdl');
          await writeFile(wsdlFile, contract, { mode: 0o600 });
          const app = await createApplication({
            service: { name: 'soap-held', version: '1.0.0', environment: 'test' },
            plugins: [
              soapPlugin({
                services: [
                  {
                    id: 'held',
                    wsdlFile,
                    endpoint: profile('/hold').endpoint,
                    protocol: '1.1',
                    allowedOperations: ['ReadStock'],
                    trustedCaRef: 'ca',
                    maxResponseBytes: 4096,
                  },
                ],
                secretProvider: {
                  async get() {
                    return { bytes: ca.slice(), keyVersion: 'v1' };
                  },
                },
                policy: {
                  maxConcurrent: 1,
                  timeoutMs: 10000,
                  maxInputBytes: 4096,
                  maxOutputBytes: 4096,
                },
              }),
            ],
          });
          try {
            await app.start();
            const client = await app.resolve<SoapService>(SOAP_CAPABILITY).createClient('held'),
              controller = new AbortController();
            const started = new Promise<void>((resolve) => {
                held = resolve;
              }),
              closed = new Promise<void>((resolve) => {
                heldClosed = resolve;
              });
            const pending = client.call(
              'ReadStock',
              { sku: '0007' },
              { signal: controller.signal },
            );
            const rejected = assert.rejects(pending, code('EK_ABORTED'));
            await started;
            const before = received;
            await assert.rejects(
              client.call('ReadStock', { sku: '0008' }),
              code('EK_BACKEND_UNAVAILABLE'),
            );
            assert.equal(received, before);
            controller.abort();
            await rejected;
            await client.close();
            await closed;
          } finally {
            held = undefined;
            heldClosed = undefined;
            await app.stop();
          }
        },
      );
      await t.test(
        'Mutual TLS rejects an absent client certificate and authenticates the configured native credential',
        async () => {
          let authenticated = 0;
          const mutual = createServer(
            {
              key,
              cert: ca,
              ca,
              requestCert: true,
              rejectUnauthorized: true,
              minVersion: 'TLSv1.2',
            },
            (request, reply) => {
              assert.ok(request.socket instanceof TLSSocket && request.socket.authorized);
              request.resume();
              request.once('end', () => {
                authenticated++;
                reply.setHeader('Content-Type', 'text/xml');
                reply.end(response);
              });
            },
          );
          mutual.on('tlsClientError', () => undefined);
          await new Promise<void>((resolve) => mutual.listen(0, '127.0.0.1', resolve));
          const address = mutual.address();
          assert.ok(address && typeof address === 'object');
          const secured = await HttpsConnection.create(
            { ...profile('/ok'), endpoint: 'https://127.0.0.1:' + address.port + '/ok' },
            new AbortController().signal,
          );
          try {
            await assert.rejects(
              secured.request(response, headers, { ca }),
              code('EK_BACKEND_UNAVAILABLE'),
            );
            assert.equal(authenticated, 0);
            assert.equal(
              (await secured.request(response, headers, { ca, cert: ca, key })).body,
              response,
            );
            assert.equal(authenticated, 1);
            const wsdlFile = join(directory, 'mutual.wsdl');
            await writeFile(wsdlFile, contract, { mode: 0o600 });
            const app = await createApplication({
              service: { name: 'soap-mutual', version: '1.0.0', environment: 'test' },
              plugins: [
                soapPlugin({
                  services: [
                    {
                      id: 'mutual',
                      wsdlFile,
                      endpoint: 'https://127.0.0.1:' + address.port + '/ok',
                      protocol: '1.1',
                      allowedOperations: ['ReadStock'],
                      credentialsRef: 'mutual',
                      trustedCaRef: 'ca',
                      maxResponseBytes: 4096,
                    },
                  ],
                  secretProvider: {
                    async get(reference) {
                      return {
                        keyVersion: 'v1',
                        bytes:
                          reference === 'ca'
                            ? ca.slice()
                            : Buffer.from(
                                JSON.stringify({
                                  version: 1,
                                  tls: {
                                    certificatePem: ca.toString(),
                                    privateKeyPem: key.toString(),
                                  },
                                }),
                              ),
                      };
                    },
                  },
                  policy: {
                    maxConcurrent: 1,
                    timeoutMs: 10000,
                    maxInputBytes: 4096,
                    maxOutputBytes: 4096,
                  },
                }),
              ],
            });
            try {
              await app.start();
              const client = await app.resolve<SoapService>(SOAP_CAPABILITY).createClient('mutual');
              assert.equal(
                (await client.call<{ quantity: number }>('ReadStock', { sku: '0007' })).data
                  .quantity,
                12,
              );
              assert.equal(authenticated, 2);
            } finally {
              await app.stop();
            }
          } finally {
            await secured.close();
            mutual.closeAllConnections();
            await new Promise<void>((resolve) => mutual.close(() => resolve()));
          }
        },
      );
      await t.test(
        'The public application capability executes a real bounded SOAP call and owns native lifecycle',
        async () => {
          let providerAvailable = true;
          const wsdlFile = join(directory, 'stock.wsdl');
          await writeFile(wsdlFile, contract, { mode: 0o600 });
          const rpcFile = join(directory, 'rpc.wsdl'),
            twelveFile = join(directory, 'twelve.wsdl');
          await writeFile(rpcFile, rpcContract, { mode: 0o600 });
          await writeFile(twelveFile, twelveContract, { mode: 0o600 });
          const app = await createApplication({
            service: { name: 'soap-runtime', version: '1.0.0', environment: 'test' },
            plugins: [
              soapPlugin({
                services: [
                  {
                    id: 'stock.v1',
                    wsdlFile,
                    endpoint: profile('/native').endpoint,
                    protocol: '1.1',
                    allowedOperations: ['ReadStock'],
                    trustedCaRef: 'ca',
                    maxResponseBytes: 4096,
                  },
                  {
                    id: 'stock.rpc',
                    wsdlFile: rpcFile,
                    endpoint: profile('/rpc').endpoint,
                    protocol: '1.1',
                    allowedOperations: ['ReadStock'],
                    trustedCaRef: 'ca',
                    maxResponseBytes: 4096,
                  },
                  {
                    id: 'stock.v12',
                    wsdlFile: twelveFile,
                    endpoint: profile('/native12').endpoint,
                    protocol: '1.2',
                    allowedOperations: ['ReadStock'],
                    trustedCaRef: 'ca',
                    maxResponseBytes: 4096,
                  },
                ],
                secretProvider: {
                  async get(reference) {
                    if (!providerAvailable) throw new Error('Private provider diagnostic');
                    assert.equal(reference, 'ca');
                    return { bytes: ca.slice(), keyVersion: 'v1' };
                  },
                },
                policy: {
                  maxConcurrent: 1,
                  timeoutMs: 10000,
                  maxInputBytes: 4096,
                  maxOutputBytes: 4096,
                },
              }),
            ],
          });
          await app.start();
          const service = app.resolve<SoapService>(SOAP_CAPABILITY);
          const client = await service.createClient('stock.v1');
          try {
            assert.deepEqual(client.describe().operations, ['ReadStock']);
            assert.equal(JSON.stringify(client), '{}');
            const result = await client.call<{ quantity: number }>('ReadStock', { sku: '0007' });
            assert.equal(result.data.quantity, 12);
            assert.equal(result.status, 200);
            assert.ok(result.headers['content-type']?.startsWith('text/xml'));
            assert.match(result.correlationId, /^[a-f0-9-]{36}$/);
            const before = nativeCalls;
            await assert.rejects(client.call('Unknown', {}), code('EK_SOAP_SCHEMA'));
            assert.equal(nativeCalls, before);
            providerAvailable = false;
            await assert.rejects(
              client.call('ReadStock', { sku: '0009' }),
              code('EK_BACKEND_UNAVAILABLE'),
            );
            assert.equal(nativeCalls, before);
            providerAvailable = true;
            const native = client.native();
            assert.ok(native instanceof Client);
            const [data] = (await native.ReadStockAsync({ sku: '0008' })) as [{ quantity: number }];
            assert.equal(data.quantity, 12);
            const nativeBefore = nativeCalls;
            await assert.rejects(
              native.ReadStockAsync({ sku: '0008' }, { timeout: 0 }),
              code('EK_CONFIG_INVALID'),
            );
            await assert.rejects(
              native.ReadStockAsync({ sku: '0008' }, { signal: AbortSignal.abort() }),
              code('EK_ABORTED'),
            );
            assert.equal(nativeCalls, nativeBefore);
            assert.throws(() => native.setEndpoint('https://other.fixture.invalid/soap'));
            assert.throws(() => native.setSecurity({}), code('EK_UNSUPPORTED_CAPABILITY'));
            await client.close();
            for (const [id, expected] of [
              ['stock.rpc', 13],
              ['stock.v12', 14],
            ] as const) {
              const other = await service.createClient(id);
              try {
                const result = await other.call<{ quantity: number }>('ReadStock', { sku: '0009' });
                assert.equal(result.data.quantity, expected);
              } finally {
                await other.close();
              }
            }
          } finally {
            await app.stop();
          }
          await assert.rejects(client.call('ReadStock', {}), code('EK_RESOURCE_CLOSED'));
          assert.throws(() => client.native(), code('EK_RESOURCE_CLOSED'));
        },
      );
      await t.test(
        'Public Basic, Bearer and native UsernameToken credentials authenticate real requests and rotate without fallback',
        async () => {
          const wsdlFile = join(directory, 'authenticated.wsdl');
          await writeFile(wsdlFile, contract, { mode: 0o600 });
          for (const mode of ['basic', 'bearer', 'wsse'] as const) {
            authenticationMode = mode;
            authenticationValue = randomUUID();
            let version = 'v1';
            const app = await createApplication({
              service: { name: 'soap-authentication', version: '1.0.0', environment: 'test' },
              plugins: [
                soapPlugin({
                  services: [
                    {
                      id: 'authenticated',
                      wsdlFile,
                      endpoint: profile('/authenticated').endpoint,
                      protocol: '1.1',
                      allowedOperations: ['ReadStock'],
                      credentialsRef: 'auth',
                      trustedCaRef: 'ca',
                      maxResponseBytes: 4096,
                    },
                  ],
                  secretProvider: {
                    async get(reference) {
                      if (reference === 'ca') return { bytes: ca.slice(), keyVersion: 'v1' };
                      const bundle =
                        mode === 'wsse'
                          ? {
                              version: 1,
                              wsSecurity: {
                                mode: 'username-token-digest',
                                username: 'fixture-user',
                                password: authenticationValue,
                              },
                            }
                          : {
                              version: 1,
                              httpAuth:
                                mode === 'basic'
                                  ? {
                                      scheme: 'basic',
                                      username: 'fixture-user',
                                      password: authenticationValue,
                                    }
                                  : { scheme: 'bearer', token: authenticationValue },
                            };
                      return { bytes: Buffer.from(JSON.stringify(bundle)), keyVersion: version };
                    },
                  },
                  policy: {
                    maxConcurrent: 1,
                    timeoutMs: 10000,
                    maxInputBytes: 8192,
                    maxOutputBytes: 4096,
                  },
                }),
              ],
            });
            await app.start();
            const client = await app
              .resolve<SoapService>(SOAP_CAPABILITY)
              .createClient('authenticated');
            try {
              assert.equal(
                (await client.call<{ quantity: number }>('ReadStock', { sku: '0007' })).data
                  .quantity,
                15,
              );
              const native = client.native();
              assert.ok(native instanceof Client);
              assert.equal((await native.ReadStockAsync({ sku: '0008' }))[0].quantity, 15);
              authenticationValue = randomUUID();
              version = 'v2';
              const before = authenticatedCalls;
              if (mode === 'wsse') {
                await assert.rejects(
                  native.ReadStockAsync({ sku: '0009' }),
                  code('EK_BACKEND_UNAVAILABLE'),
                );
                assert.equal(authenticatedCalls, before);
              }
              assert.equal(
                (await client.call<{ quantity: number }>('ReadStock', { sku: '0009' })).data
                  .quantity,
                15,
              );
              assert.equal(authenticatedCalls, before + 1);
              assert.equal(JSON.stringify(client), '{}');
            } finally {
              await app.stop();
            }
          }
        },
      );
    } finally {
      await connection.close();
    }
  },
);
