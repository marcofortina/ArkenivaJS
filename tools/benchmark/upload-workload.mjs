// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { request } from 'node:http';
import { Readable } from 'node:stream';
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
async function consume(source, native) {
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
      continue;
    }
    const hash = createHash('sha256');
    for await (const chunk of native ? part.file : part.stream) {
      bytes += chunk.byteLength;
      hash.update(chunk);
    }
    if (native) assert.equal(part.file.truncated, false);
    digests.push(hash.digest('hex'));
  }
  return { bytes, digests, order, note };
}

export function uploadSettings() {
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
        handler: (input) => consume(input.parts, false),
      },
    ],
  };
}

export async function nativeUpload() {
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
    consume(input.parts(), true),
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
  };
}

/** Construct a fresh single-pass multipart source for each actual network transfer. */
export async function sendUpload(service, fixture, fragmented) {
  const origin = new URL(service.address());
  assert.equal(origin.protocol, 'http:');
  assert.equal(origin.hostname, '127.0.0.1');
  assert.ok(origin.port.length > 0);
  const payload = Buffer.from(fixture.marker.repeat(4096), 'utf8');
  assert.ok(payload.length > 65536 && payload.length <= uploadPolicy.maxFileBytes);
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
