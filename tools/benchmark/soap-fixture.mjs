// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { listen } from 'soap';
import { contract } from '../../packages/soap/dist-test/fixture.js';
import { soapReceiptDigest } from './soap-workload.mjs';

/** Reuse the conformance WSDL; the independent native server owns bounded TLS/XML observations. */
export async function startSoapFixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-soap-comparison-')),
    certificateFile = join(directory, 'server.pem'),
    keyFile = join(directory, 'server.key'),
    wsdlFile = join(directory, 'contract.wsdl'),
    records = [],
    sockets = new Set(),
    contexts = new WeakMap(),
    privacyValues = [],
    state = {
      decodedCalls: 0,
      completedReplies: 0,
      failedRequests: 0,
      observedRequestXmlBytes: 0,
      observedResponseXmlBytes: 0,
      activeRequests: 0,
      peakActiveRequests: 0,
      activeConnections: 0,
      peakConnections: 0,
    };
  let server, nativeServer;
  const quiescent = async () => {
    for (let attempt = 0; attempt < 500; attempt++) {
      if (state.activeRequests === 0 && sockets.size === 0) return;
      await delay(10);
    }
    throw new Error('The owned SOAP physical resources did not retire');
  };
  const close = async () => {
    try {
      if (server?.listening) {
        server.closeAllConnections();
        for (const socket of sockets) socket.destroy();
        await new Promise((done) => server.close(done));
      }
      await quiescent();
    } finally {
      records.length = 0;
      await rm(directory, { recursive: true, force: true });
    }
  };
  try {
    await chmod(directory, 0o700);
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
        '/CN=Owned SOAP Comparison',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        keyFile,
        '-out',
        certificateFile,
      ],
      { timeout: 10000, maxBuffer: 65536 },
    );
    await chmod(keyFile, 0o600);
    await writeFile(wsdlFile, contract, { mode: 0o600, flag: 'wx' });
    const marker = '0007-owned-soap-private-sku-π';
    server = createServer(
      {
        key: await readFile(keyFile),
        cert: await readFile(certificateFile),
        minVersion: 'TLSv1.2',
      },
      (_request, response) => response.writeHead(404).end(),
    );
    server.maxConnections = 4;
    server.requestTimeout = 3000;
    server.headersTimeout = 3000;
    server.on('tlsClientError', () => undefined);
    server.on('connection', (socket) => {
      sockets.add(socket);
      state.activeConnections = sockets.size;
      state.peakConnections = Math.max(state.peakConnections, sockets.size);
      socket.once('close', () => {
        sockets.delete(socket);
        state.activeConnections = sockets.size;
      });
    });
    await new Promise((done, reject) => {
      nativeServer = listen(
        server,
        '/soap',
        {
          InventoryService: {
            InventoryPort: {
              ReadStock(value, _callback, _headers, request, response) {
                const context = contexts.get(request);
                try {
                  assert.ok(context && !context.decoded);
                  assert.ok(value.sku === marker + '-0' || value.sku === marker + '-1');
                  assert.deepEqual(Object.keys(value), ['sku']);
                  context.index = value.sku === marker + '-0' ? 0 : 1;
                  context.receipt = randomUUID();
                  context.decoded = true;
                  state.decodedCalls++;
                  privacyValues.push(context.receipt);
                  response.setHeader('x-owned-soap-receipt', context.receipt);
                  return { quantity: 12 };
                } catch {
                  state.failedRequests++;
                  throw new Error('The owned SOAP fixture rejected its request');
                }
              },
            },
          },
        },
        contract,
        (cause) => (cause ? reject(cause) : done()),
      );
    });
    // Native server admission runs before its existing XML parser and bounded source capture.
    nativeServer.authorizeConnection = (request, response) => {
      const size = Number(request.headers['content-length']);
      if (
        request.method !== 'POST' ||
        request.url !== '/soap' ||
        !request.socket.encrypted ||
        !Number.isSafeInteger(size) ||
        size < 1 ||
        size > 4096 ||
        request.headers['transfer-encoding'] !== undefined ||
        request.headers['content-encoding'] !== undefined ||
        state.activeRequests >= 4 ||
        records.length + state.activeRequests >= 512
      ) {
        state.failedRequests++;
        response.statusCode = 400;
        return false;
      }
      const context = {
        inputBytes: 0,
        outputBytes: 0,
        decoded: false,
        retired: false,
        failed: false,
        responseChunks: [],
      };
      contexts.set(request, context);
      state.activeRequests++;
      state.peakActiveRequests = Math.max(state.peakActiveRequests, state.activeRequests);
      const fail = () => {
        if (!context.failed) state.failedRequests++;
        context.failed = true;
      };
      const retire = () => {
        if (context.retired) return;
        context.retired = true;
        context.responseChunks.length = 0;
        state.activeRequests--;
      };
      request.on('data', (chunk) => {
        context.inputBytes += chunk.length;
        if (context.inputBytes > 4096 || context.inputBytes > size) {
          fail();
          request.destroy(new Error('The owned SOAP XML capacity was exceeded'));
        }
      });
      request.once('end', () => {
        if (context.inputBytes !== size) {
          fail();
          response.destroy();
        }
      });
      request.once('error', () => {
        fail();
        response.destroy();
      });
      const capture = (chunk, encoding) => {
        if (chunk === undefined || chunk === null) return true;
        const bytes = Buffer.isBuffer(chunk)
          ? chunk
          : Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8');
        context.outputBytes += bytes.length;
        if (context.outputBytes > 4096) {
          fail();
          response.destroy();
          return false;
        }
        context.responseChunks.push(bytes);
        return true;
      };
      const write = response.write,
        end = response.end;
      response.write = function (chunk, ...args) {
        if (!capture(chunk, args[0])) return false;
        return Reflect.apply(write, this, [chunk, ...args]);
      };
      response.end = function (chunk, ...args) {
        if (!capture(chunk, args[0])) return this;
        return Reflect.apply(end, this, [chunk, ...args]);
      };
      response.once('finish', () => {
        try {
          assert.equal(context.failed, false);
          assert.equal(context.decoded, true);
          assert.equal(response.statusCode, 200);
          assert.equal(response.getHeader('x-owned-soap-receipt'), context.receipt);
          const parsed = nativeServer.wsdl.xmlToObject(
            Buffer.concat(context.responseChunks).toString('utf8'),
          );
          assert.deepEqual(parsed.Body.ReadStockResponse, { quantity: 12 });
          records.push({ receipt: context.receipt, index: context.index, quantity: 12 });
          state.completedReplies++;
          state.observedRequestXmlBytes += context.inputBytes;
          state.observedResponseXmlBytes += context.outputBytes;
        } catch {
          fail();
        } finally {
          retire();
        }
      });
      response.once('close', () => {
        if (!context.retired) {
          fail();
          retire();
        }
      });
      return true;
    };
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    const fixture = {
      endpoint: 'https://127.0.0.1:' + server.address().port + '/soap',
      certificateFile,
      wsdlFile,
      marker,
    };
    privacyValues.push(...Object.values(fixture), '127.0.0.1', 'localhost');
    return {
      fixture,
      privacyValues,
      close,
      quiescent,
      verify(expectedCalls, profiles, measured = false) {
        assert.equal(state.failedRequests, 0);
        assert.equal(records.length, expectedCalls);
        assert.equal(state.decodedCalls, expectedCalls);
        assert.equal(state.completedReplies, expectedCalls);
        assert.equal(records.filter((row) => row.index === 0).length, expectedCalls / 2);
        assert.equal(records.filter((row) => row.index === 1).length, expectedCalls / 2);
        assert.equal(new Set(records.map((row) => row.receipt)).size, expectedCalls);
        if (profiles) {
          let offset = 0;
          for (const profile of profiles) {
            const next = offset + profile.totalCalls;
            assert.ok(Number.isSafeInteger(next) && next <= records.length);
            const rows = records.slice(offset, next);
            assert.equal(soapReceiptDigest(rows), profile.receiptDigest);
            assert.deepEqual(
              [
                rows.filter((row) => row.index === 0).length,
                rows.filter((row) => row.index === 1).length,
              ],
              profile.inputCounts,
            );
            offset = next;
          }
          assert.equal(offset, records.length);
        }
        return {
          actualNativeRequests: records.length,
          distinctInputsVerified: true,
          releaseGate: false,
          ...(measured
            ? {
                measured: true,
                independentReceiptIntegrity: true,
                decodedResponseCount: state.completedReplies,
                observedRequestXmlBytes: state.observedRequestXmlBytes,
                observedResponseXmlBytes: state.observedResponseXmlBytes,
                activeRequests: state.activeRequests,
                activeConnections: state.activeConnections,
                peakActiveRequests: state.peakActiveRequests,
                peakConnections: state.peakConnections,
                failedRequests: state.failedRequests,
              }
            : {}),
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
