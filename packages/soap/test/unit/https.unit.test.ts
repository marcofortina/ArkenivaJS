// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:https';
import { TLSSocket } from 'node:tls';
import { setInterval, clearInterval } from 'node:timers';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from 'soap';
import type { IHttpClient } from 'soap';
import { KitError } from '@arkenivajs/core';
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
      disconnected = 0;
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
          } finally {
            await secured.close();
            mutual.closeAllConnections();
            await new Promise<void>((resolve) => mutual.close(() => resolve()));
          }
        },
      );
    } finally {
      await connection.close();
    }
  },
);
