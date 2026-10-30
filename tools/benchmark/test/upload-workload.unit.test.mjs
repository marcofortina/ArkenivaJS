// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { setImmediate } from 'node:timers';
import { createApplication, COMPONENTS } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { apiPlugin } from '@arkenivajs/api';
import { uploadPlugin, UPLOAD_CAPABILITY } from '@arkenivajs/upload';
import {
  nativeUpload,
  verifyUpload,
  sendUpload,
  uploadObservation,
  uploadSettings,
  prepareUpload,
  uploadWorkload,
} from '../upload-workload.mjs';

test('Native multipart consumes fresh chunked sources, exact UTF8 fields, empty files and actual hashes', async () => {
  const fixture = { marker: 'owned-upload-content-π', note: 'owned-upload-field-€' },
    native = await nativeUpload();
  try {
    const result = await verifyUpload(native, fixture);
    assert.equal(result.consumedFileBytes, Buffer.byteLength(fixture.marker) * 4096 * 2);
    assert.equal(result.completedFiles, 4);
    await assert.rejects(sendUpload({ address: () => 'http://example.invalid:1' }, fixture, true));
  } finally {
    await native.close();
  }
});

test(
  'Four upload profiles verify streamed protocol and actual private SDK exports without performance claims',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-upload-harness-')),
      script = fileURLToPath(new URL('../upload.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(
        encoded,
        /owned-upload-content|owned-upload-field|owned\.bin|empty\.bin|127\.0\.0\.1/,
      );
      for (const row of report.records) {
        assert.equal(row.records.length, 0);
        assert.equal(row.resource, null);
        assert.deepEqual(row.verification, {
          completedRequests: 2,
          completedFiles: 4,
          consumedFileBytes: Buffer.byteLength('owned-upload-content-π') * 4096 * 2,
          orderedParts: true,
          emptyFileVerified: true,
          fragmentedUtf8: true,
        });
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      for (const mode of ['--smoke', '--full']) {
        const rejected = join(directory, mode.slice(2));
        await assert.rejects(
          promisify(execFile)(process.execPath, [script, mode, rejected], {
            timeout: 5000,
            maxBuffer: 1048576,
            env: { ...process.env, ARKENIVA_UPLOAD_BENCHMARK_DISPOSABLE: '' },
          }),
        );
        await assert.rejects(access(rejected), { code: 'ENOENT' });
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'Native and public multipart callbacks reconcile real sink data and retire source, sockets and sinks',
  { timeout: 20000 },
  async () => {
    const fixture = { marker: 'owned-upload-content-π', note: 'owned-upload-field-€' },
      native = await nativeUpload(),
      observation = uploadObservation(),
      sink = new Writable({
        write(_chunk, _encoding, done) {
          done();
        },
      });
    let app;
    try {
      app = await createApplication({
        service: { name: 'upload-bounded-callback-test', version: '1.0.0', environment: 'test' },
        http: { host: '127.0.0.1', port: 0, requestTimeoutMs: 5000 },
        plugins: [
          loggingPlugin({ destination: sink }),
          apiPlugin(),
          uploadPlugin(uploadSettings(observation)),
        ],
      });
      await app.start();
      const api = app.resolve(COMPONENTS.api),
        upload = app.resolve(UPLOAD_CAPABILITY);
      const publicService = { address: () => api.address(), observation };
      for (const service of [native, publicService]) {
        prepareUpload(service, fixture);
        const result = await uploadWorkload(service).streamedMultipart();
        assert.equal(result.fileBytes, Buffer.byteLength(fixture.marker) * 4096);
        assert.equal(result.digestsVerified, true);
        assert.equal(result.sourceRetired, true);
        assert.equal(result.connectionClosed, true);
        assert.equal(result.closedSinks, 2);
        assert.ok(result.drainWaits > 0 && result.drainWaitMs >= 0);
        assert.ok(result.firstFileByteMs >= 0);
        assert.ok(result.firstResponseByteMs >= result.firstFileByteMs);
        assert.ok(result.elapsedMs >= result.firstResponseByteMs);
        assert.ok(result.largestSourceChunkBytes <= 24576);
        assert.ok(result.sinkChunks > 0 && result.sinkPeakQueuedBytes > 0);
        assert.equal(service.observation.completedRequests, 1);
        assert.equal(service.observation.completedFiles, 2);
        assert.equal(service.observation.completedParts, 3);
        assert.equal(service.observation.fileBytes, result.fileBytes);
        assert.equal(service.observation.fieldBytes, Buffer.byteLength(fixture.note));
        assert.equal(service.observation.current, undefined);
        if (service === publicService) {
          const stats = upload.stats();
          assert.equal(stats.activeRequests, 0);
          assert.equal(stats.receivedRequests, 1);
          assert.equal(stats.successfulRequests, 1);
          assert.equal(stats.rejectedRequests, 0);
          assert.equal(stats.observedBytes, result.emittedBodyBytes);
        }
      }
    } finally {
      await app?.stop();
      await native.close();
      sink.destroy();
    }
  },
);

test(
  'A successful HTTP status cannot replace independently verified multipart digests',
  { timeout: 10000 },
  async () => {
    let connections = 0,
      receivedBodyBytes = 0;
    const server = createServer(async (incoming, response) => {
      for await (const chunk of incoming) receivedBodyBytes += chunk.length;
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ bytes: 0, digests: [], order: [], note: '' }));
    });
    server.on('connection', (socket) => {
      connections++;
      socket.once('close', () => connections--);
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const service = {
      address: () => 'http://127.0.0.1:' + server.address().port,
      observation: uploadObservation(),
    };
    try {
      prepareUpload(service, { marker: 'owned-upload-content-π', note: 'owned-upload-field-€' });
      await assert.rejects(uploadWorkload(service).streamedMultipart(), { code: 'ERR_ASSERTION' });
      assert.equal(service.observation.current, undefined);
      assert.ok(receivedBodyBytes > Buffer.byteLength('owned-upload-content-π') * 4096);
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(connections, 0);
    } finally {
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  },
);
