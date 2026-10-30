// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { request } from 'node:http';
import { once } from 'node:events';
import { performance } from 'node:perf_hooks';
import { setImmediate } from 'node:timers';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import Fastify from 'fastify';
import multipart from '@fastify/multipart';

export const uploadPolicy = {
  maxRequestBytes: 1048576,
  maxFileBytes: 262144,
  maxFiles: 2,
  maxFields: 1,
  maxFieldBytes: 1024,
  maxParts: 3,
  allowedMediaTypes: ['application/octet-stream'],
};
export const uploadResponse = {
  type: 'object',
  properties: {
    bytes: { type: 'integer' },
    digests: { type: 'array', items: { type: 'string' } },
    order: { type: 'array', items: { type: 'string' } },
    note: { type: 'string' },
  },
  required: ['bytes', 'digests', 'order', 'note'],
  additionalProperties: false,
};

/** Both adapters digest actual consumed chunks; neither buffers complete files. */
async function consume(source, native, observation) {
  let bytes = 0,
    note = '';
  const digests = [],
    order = [];
  for await (const part of source) {
    const file = native ? part.type === 'file' : part.kind === 'file';
    const name = native ? part.fieldname : part.fieldName;
    order.push((file ? 'file:' : 'field:') + name);
    if (!file) {
      note = part.value;
      if (observation) observation.fieldBytes += Buffer.byteLength(part.value, 'utf8');
      continue;
    }
    const hash = createHash('sha256');
    const input = native ? part.file : part.stream;
    if (observation?.current) {
      const current = observation.current;
      const sink = new Writable({
        highWaterMark: 4096,
        write(chunk, _encoding, done) {
          current.firstFileByteMs ??= performance.now() - current.started;
          current.sinkPeakQueuedBytes = Math.max(current.sinkPeakQueuedBytes, sink.writableLength);
          current.largestSinkChunkBytes = Math.max(current.largestSinkChunkBytes, chunk.length);
          current.sinkChunks++;
          bytes += chunk.length;
          hash.update(chunk);
          // A cooperative application sink makes actual stream pressure observable.
          setImmediate(done);
        },
      });
      assert.equal(sink.writableHighWaterMark, 4096);
      await pipeline(Readable.from(input, { objectMode: false, highWaterMark: 16384 }), sink);
      assert.equal(sink.writableFinished, true);
      assert.equal(sink.closed, true);
      current.closedSinks++;
    } else
      for await (const chunk of input) {
        bytes += chunk.byteLength;
        hash.update(chunk);
      }
    if (native) assert.equal(part.file.truncated, false);
    digests.push(hash.digest('hex'));
  }
  if (observation) {
    observation.completedRequests++;
    observation.completedFiles += digests.length;
    observation.completedParts += order.length;
    observation.fileBytes += bytes;
  }
  return { bytes, digests, order, note };
}

export function uploadObservation() {
  return {
    completedRequests: 0,
    completedFiles: 0,
    completedParts: 0,
    fileBytes: 0,
    fieldBytes: 0,
  };
}

export function uploadSettings(observation) {
  return {
    routes: [
      {
        path: '/uploads',
        method: 'POST',
        policy: uploadPolicy,
        auth: {
          required: false,
          reason: 'Owned loopback protocol comparison with synthetic nonsecret input only',
        },
        responseSchema: uploadResponse,
        handler: (input) => consume(input.parts, false, observation),
      },
    ],
  };
}

export async function nativeUpload() {
  const observation = uploadObservation();
  const server = Fastify({ logger: false, bodyLimit: uploadPolicy.maxRequestBytes });
  server.register(multipart, {
    limits: {
      fileSize: uploadPolicy.maxFileBytes,
      files: uploadPolicy.maxFiles,
      fields: uploadPolicy.maxFields,
      fieldSize: uploadPolicy.maxFieldBytes,
      parts: uploadPolicy.maxParts,
    },
  });
  server.post('/uploads', { schema: { response: { 200: uploadResponse } } }, (input) =>
    consume(input.parts(), true, observation),
  );
  try {
    await server.listen({ host: '127.0.0.1', port: 0 });
  } catch (error) {
    await server.close();
    throw error;
  }
  return {
    address: () => 'http://127.0.0.1:' + server.server.address().port,
    close: () => server.close(),
    observation,
  };
}

function envelope(fixture) {
  const boundary = 'arkenivajs-owned-multipart-boundary';
  const prefix = Buffer.from(
    '--' + boundary + '\r\nContent-Disposition: form-data; name="note"\r\n\r\n',
  );
  const note = Buffer.from(fixture.note, 'utf8');
  const fileHeader = Buffer.from(
    '\r\n--' +
      boundary +
      '\r\nContent-Disposition: form-data; name="document"; filename="owned.bin"\r\nContent-Type: application/octet-stream\r\n\r\n',
  );
  const suffix = Buffer.from(
    '\r\n--' +
      boundary +
      '\r\nContent-Disposition: form-data; name="empty"; filename="empty.bin"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n--' +
      boundary +
      '--\r\n',
  );
  return { boundary, prefix, note, fileHeader, suffix };
}

function uploadOrigin(service) {
  const origin = new URL(service.address());
  assert.equal(origin.protocol, 'http:');
  assert.equal(origin.hostname, '127.0.0.1');
  assert.ok(origin.port.length > 0);
  return origin;
}

/** Construct a fresh single-pass multipart source for each actual network transfer. */
export async function sendUpload(service, fixture, fragmented) {
  const origin = uploadOrigin(service),
    payload = Buffer.from(fixture.marker.repeat(4096), 'utf8'),
    { boundary, prefix, note, fileHeader, suffix } = envelope(fixture);
  assert.ok(payload.length > 65536 && payload.length <= uploadPolicy.maxFileBytes);
  let consumed = false,
    emittedBytes = 0;
  const source = Readable.from(
    (async function* () {
      assert.equal(consumed, false);
      consumed = true;
      for (const section of [prefix, note, fileHeader, payload, suffix]) {
        let offset = 0,
          turn = 0;
        while (offset < section.length) {
          const size = fragmented ? (section === note ? 1 : [1, 7, 1024, 8192][turn++ % 4]) : 8192;
          const chunk = section.subarray(offset, offset + size);
          offset += chunk.length;
          emittedBytes += chunk.length;
          yield chunk;
        }
      }
    })(),
    { objectMode: false, highWaterMark: 16384 },
  );
  let outgoing;
  const response = new Promise((resolve, reject) => {
    outgoing = request(
      new URL('/uploads', origin),
      {
        method: 'POST',
        agent: false,
        signal: AbortSignal.timeout(5000),
        headers: { 'content-type': 'multipart/form-data; boundary=' + boundary },
      },
      (incoming) => {
        let body = '';
        incoming.on('data', (chunk) => {
          body += chunk.toString('utf8');
          if (Buffer.byteLength(body) > 4096)
            incoming.destroy(new Error('The upload receipt exceeds its capacity'));
        });
        incoming.once('error', reject);
        incoming.once('end', () => {
          try {
            assert.equal(incoming.statusCode, 200);
            resolve(JSON.parse(body));
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    outgoing.once('error', reject);
  });
  const [receipt] = await Promise.all([response, pipeline(source, outgoing)]);
  assert.equal(
    emittedBytes,
    prefix.length + note.length + fileHeader.length + payload.length + suffix.length,
  );
  assert.deepEqual(receipt, {
    bytes: payload.length,
    digests: [
      createHash('sha256').update(payload).digest('hex'),
      createHash('sha256').digest('hex'),
    ],
    order: ['field:note', 'file:document', 'file:empty'],
    note: fixture.note,
  });
  return receipt.bytes;
}

export async function verifyUpload(service, fixture) {
  const bytes =
    (await sendUpload(service, fixture, false)) + (await sendUpload(service, fixture, true));
  if (service.stats) assert.equal(service.stats().observerFailures, 0);
  return {
    completedRequests: 2,
    completedFiles: 4,
    consumedFileBytes: bytes,
    orderedParts: true,
    emptyFileVerified: true,
    fragmentedUtf8: true,
  };
}

const sampling = new WeakMap();

export function prepareUpload(service, fixture) {
  assert.ok(service.observation);
  assert.equal(sampling.has(service), false);
  const pattern = Buffer.from(fixture.marker, 'utf8'),
    fileBytes = pattern.length * 4096,
    block = Buffer.alloc(pattern.length * Math.floor(8192 / pattern.length)),
    parts = envelope(fixture),
    hash = createHash('sha256');
  assert.ok(fileBytes > 65536 && fileBytes <= uploadPolicy.maxFileBytes);
  assert.ok(block.length > 0 && block.length <= 8192);
  block.fill(pattern);
  for (let index = 0; index < 4096; index++) hash.update(pattern);
  const bodyBytes =
    parts.prefix.length +
    parts.note.length +
    parts.fileHeader.length +
    fileBytes +
    parts.suffix.length;
  assert.ok(bodyBytes <= uploadPolicy.maxRequestBytes);
  sampling.set(service, {
    block,
    parts,
    fileBytes,
    bodyBytes,
    measurements: [],
    expectedReceipt: {
      bytes: fileBytes,
      digests: [hash.digest('hex'), createHash('sha256').digest('hex')],
      order: ['field:note', 'file:document', 'file:empty'],
      note: fixture.note,
    },
    before: { ...service.observation },
    uploadBefore: service.uploadStats?.(),
  });
}

/** Timing ends only after the source, response, connection and both sinks retire. */
async function sampledUpload(service) {
  const state = sampling.get(service);
  assert.ok(state && state.measurements.length < 120);
  const origin = uploadOrigin(service),
    current = {
      started: performance.now(),
      firstFileByteMs: null,
      firstResponseByteMs: null,
      sourcePeakQueuedBytes: 0,
      clientPeakQueuedBytes: 0,
      sinkPeakQueuedBytes: 0,
      largestSourceChunkBytes: 0,
      largestSinkChunkBytes: 0,
      sinkChunks: 0,
      drainWaits: 0,
      drainWaitMs: 0,
      emittedBodyBytes: 0,
      closedSinks: 0,
      sourceRetired: false,
    };
  assert.equal(service.observation.current, undefined);
  service.observation.current = current;
  const { parts, block } = state;
  const source = Readable.from(
    (async function* () {
      try {
        for (const section of [parts.prefix, parts.note, parts.fileHeader])
          for (let offset = 0; offset < section.length; offset++)
            yield section.subarray(offset, offset + 1);
        for (let remaining = state.fileBytes; remaining > 0;) {
          const chunk = block.subarray(0, Math.min(remaining, block.length));
          remaining -= chunk.length;
          yield chunk;
        }
        for (let offset = 0; offset < parts.suffix.length; offset += 7)
          yield parts.suffix.subarray(offset, offset + 7);
      } finally {
        current.sourceRetired = true;
      }
    })(),
    { objectMode: false, highWaterMark: 16384 },
  );
  let outgoing, incoming, socket;
  const sourceClosed = new Promise((resolve) => source.once('close', resolve)),
    response = new Promise((resolve, reject) => {
      outgoing = request(
        new URL('/uploads', origin),
        {
          method: 'POST',
          agent: false,
          signal: AbortSignal.timeout(5000),
          highWaterMark: 4096,
          headers: { 'content-type': 'multipart/form-data; boundary=' + parts.boundary },
        },
        (value) => {
          incoming = value;
          const chunks = [];
          let bytes = 0;
          incoming.on('data', (chunk) => {
            current.firstResponseByteMs ??= performance.now() - current.started;
            bytes += chunk.length;
            if (bytes > 4096)
              incoming.destroy(new Error('The upload receipt exceeds its capacity'));
            else chunks.push(chunk);
          });
          incoming.once('error', reject);
          incoming.once('end', () => {
            try {
              assert.equal(incoming.statusCode, 200);
              resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch (error) {
              reject(error);
            }
          });
        },
      );
      outgoing.once('error', reject);
    });
  // An early HTTP error is retained until the producer reaches its cleanup boundary.
  void response.catch(() => undefined);
  const requestClosed = new Promise((resolve) => outgoing.once('close', resolve));
  const socketClosed = new Promise((resolve) => {
    outgoing.once('socket', (value) => {
      socket = value;
      socket.once('close', resolve);
    });
    outgoing.once('error', () => {
      if (!socket) resolve();
    });
  });
  try {
    for await (const chunk of source) {
      current.emittedBodyBytes += chunk.length;
      current.largestSourceChunkBytes = Math.max(current.largestSourceChunkBytes, chunk.length);
      current.sourcePeakQueuedBytes = Math.max(
        current.sourcePeakQueuedBytes,
        source.readableLength,
      );
      const accepted = outgoing.write(chunk);
      current.clientPeakQueuedBytes = Math.max(
        current.clientPeakQueuedBytes,
        outgoing.writableLength,
      );
      if (!accepted) {
        const started = performance.now();
        current.drainWaits++;
        await once(outgoing, 'drain');
        current.drainWaitMs += performance.now() - started;
      }
    }
    outgoing.end();
    const receipt = await response;
    await Promise.all([sourceClosed, requestClosed, socketClosed]);
    assert.deepEqual(receipt, state.expectedReceipt);
    assert.equal(current.emittedBodyBytes, state.bodyBytes);
    assert.equal(current.sourceRetired, true);
    assert.equal(source.readableHighWaterMark, 16384);
    assert.equal(outgoing.writableHighWaterMark, 4096);
    assert.equal(source.closed, true);
    assert.equal(outgoing.writableFinished, true);
    assert.equal(socket.destroyed, true);
    assert.equal(current.closedSinks, 2);
    assert.equal(typeof current.firstFileByteMs, 'number');
    assert.equal(typeof current.firstResponseByteMs, 'number');
    assert.ok(
      current.firstFileByteMs >= 0 && current.firstResponseByteMs >= current.firstFileByteMs,
    );
    assert.ok(current.drainWaits > 0);
    assert.ok(current.largestSourceChunkBytes <= 24576);
    assert.ok(current.sourcePeakQueuedBytes <= 24576);
    assert.ok(current.clientPeakQueuedBytes <= uploadPolicy.maxRequestBytes);
    assert.ok(current.sinkPeakQueuedBytes <= uploadPolicy.maxFileBytes);
    const { started, ...measurement } = current;
    measurement.elapsedMs = performance.now() - started;
    measurement.fileBytes = receipt.bytes;
    measurement.fileBytesPerSecond = (receipt.bytes * 1000) / measurement.elapsedMs;
    measurement.httpBodyBytesPerSecond = (state.bodyBytes * 1000) / measurement.elapsedMs;
    measurement.digestsVerified = true;
    measurement.connectionClosed = true;
    state.measurements.push(measurement);
    return measurement;
  } finally {
    incoming?.destroy();
    outgoing.destroy();
    source.destroy();
    await Promise.allSettled([sourceClosed, requestClosed, socketClosed, response]);
    delete service.observation.current;
  }
}

export function uploadWorkload(service) {
  return { streamedMultipart: () => sampledUpload(service) };
}

export function completeUpload(service, { measure, records }) {
  if (!measure) {
    assert.equal(sampling.has(service), false);
    return { sampledRequests: 0, warmupRequests: 0, checkedRequests: 0 };
  }
  const state = sampling.get(service);
  try {
    assert.ok(state);
    assert.equal(records.length, 1);
    assert.equal(records[0].sampleCount, 100);
    assert.equal(records[0].warmupIterations, 20);
    assert.equal(state.measurements.length, 120);
    const current = service.observation,
      before = state.before;
    assert.equal(current.completedRequests - before.completedRequests, 120);
    assert.equal(current.completedFiles - before.completedFiles, 240);
    assert.equal(current.completedParts - before.completedParts, 360);
    assert.equal(current.fileBytes - before.fileBytes, state.fileBytes * 120);
    assert.equal(current.fieldBytes - before.fieldBytes, state.parts.note.length * 120);
    const stats = service.uploadStats?.();
    if (stats) {
      assert.equal(stats.activeRequests, 0);
      assert.equal(stats.receivedRequests - state.uploadBefore.receivedRequests, 120);
      assert.equal(stats.successfulRequests - state.uploadBefore.successfulRequests, 120);
      assert.equal(stats.rejectedRequests - state.uploadBefore.rejectedRequests, 0);
      assert.equal(stats.observedBytes - state.uploadBefore.observedBytes, state.bodyBytes * 120);
    }
    if (service.stats) assert.equal(service.stats().observerFailures, 0);
    return {
      sampledRequests: 100,
      warmupRequests: 20,
      checkedRequests: 120,
      independentlyConsumedFiles: 240,
      independentlyConsumedParts: 360,
      consumedFileBytes: state.fileBytes * 120,
      consumedFieldBytes: state.parts.note.length * 120,
      emittedHttpBodyBytes: state.bodyBytes * 120,
      frameworkObservedHttpBodyBytes: stats
        ? stats.observedBytes - state.uploadBefore.observedBytes
        : null,
      observedDrainWaits: state.measurements.reduce((sum, item) => sum + item.drainWaits, 0),
      opaqueParserAndKernelBufferBytes: null,
      measurements: state.measurements,
    };
  } finally {
    sampling.delete(service);
  }
}
