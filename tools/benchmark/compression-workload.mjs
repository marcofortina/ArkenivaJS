// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createGzip, createGunzip, gzipSync, gunzipSync } from 'node:zlib';
import { Readable } from 'node:stream';
import { pipeline, finished } from 'node:stream/promises';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { zipSync, unzipSync } from 'fflate';
import { fromBufferPromise } from 'yauzl';

export const compressionFixture = Object.freeze({
  marker: 'owned-compression-fixture',
  first: 'alpha.txt',
  second: 'nested/beta.bin',
});
export const compressionSettings = Object.freeze({
  defaults: Object.freeze({}),
  policy: Object.freeze({ maxConcurrent: 1, timeoutMs: 5000 }),
});
export const payload = Buffer.from(
  Array.from(
    { length: 64 },
    (_, index) => `${compressionFixture.marker}:${index.toString().padStart(3, '0')}\n`,
  ).join(''),
);
export const entries = () => [
  { path: compressionFixture.first, data: Buffer.from(payload) },
  { path: compressionFixture.second, data: Buffer.from([0, 255, 1, 254]) },
];
export async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function* nativeGzip(input, decode) {
  const source = Readable.from(input instanceof Uint8Array ? [input] : input, {
      objectMode: false,
      highWaterMark: 16384,
    }),
    codec = decode
      ? createGunzip({ chunkSize: 16384 })
      : createGzip({ chunkSize: 16384, level: 6 });
  const task = pipeline(source, codec);
  void task.catch(() => undefined);
  try {
    for await (const chunk of codec) yield chunk;
    await task;
  } finally {
    source.destroy();
    codec.destroy();
  }
}
/** Bare SDK operations consume a fixed finite corpus, never untrusted remote archives. */
export function nativeCompression() {
  return {
    gzip: (input) => nativeGzip(input, false),
    gunzip: (input) => nativeGzip(input, true),
    async *createZip(input) {
      const files = {};
      for await (const entry of input)
        files[entry.path] =
          entry.data instanceof Uint8Array ? entry.data : await collect(entry.data);
      yield zipSync(files, { level: 6 });
    },
    async *iterateZip(input) {
      const zip = await fromBufferPromise(
        input instanceof Uint8Array ? Buffer.from(input) : await collect(input),
        { autoClose: false, strictFileNames: true, validateEntrySizes: true },
      );
      try {
        for await (const entry of zip.eachEntry()) {
          const stream = await zip.openReadStreamPromise(entry);
          yield {
            path: entry.fileName,
            type: 'file',
            sizeBytes: entry.uncompressedSize,
            data: stream,
          };
        }
      } finally {
        zip.close();
      }
    },
  };
}

export async function archiveContents(service, archive) {
  const result = {};
  for await (const entry of service.iterateZip(archive))
    result[entry.path] = await collect(entry.data);
  return result;
}
const observations = new WeakMap();

export async function verifyCompression(service) {
  const encoded = await collect(service.gzip(payload));
  assert.deepEqual(gunzipSync(encoded), payload);
  assert.deepEqual(await collect(service.gunzip(gzipSync(payload))), payload);
  const archive = await collect(service.createZip(entries()));
  const expected = Object.fromEntries(
    entries().map((entry) => [entry.path, Buffer.from(entry.data)]),
  );
  const direct = unzipSync(archive);
  for (const [name, bytes] of Object.entries(expected))
    assert.deepEqual(Buffer.from(direct[name]), bytes);
  assert.deepEqual(await archiveContents(service, archive), expected);
  const empty = await collect(service.gzip(new Uint8Array()));
  assert.equal(gunzipSync(empty).length, 0);
  observations.set(service, { corpus: compressionSmallCorpus(), calls: { gzip: [], gunzip: [] } });
  return {
    checkedGzipRoundtrips: 3,
    checkedZipEntries: 2,
    completedStreams: true,
    inputBytes: payload.byteLength,
  };
}

const hash = () => createHash('sha256');

export function compressionSmallCorpus() {
  const encoded = gzipSync(payload, { level: 6 });
  assert.ok(encoded.length <= 65536 && payload.length <= 65536);
  return {
    encoded,
    plainDigest: hash().update(payload).digest('hex'),
    encodedDigest: hash().update(encoded).digest('hex'),
  };
}

/** Tiny corpus observations are functional byte/CRC checks as well as diagnostic stream timings. */
export async function compressionSmallOperation(
  service,
  operation,
  corpus = compressionSmallCorpus(),
) {
  assert.ok(operation === 'gzip' || operation === 'gunzip');
  const sourceBytes = operation === 'gzip' ? payload : corpus.encoded,
    expectedInputDigest = operation === 'gzip' ? corpus.plainDigest : corpus.encodedDigest,
    outputDigest = hash(),
    inputDigest = hash(),
    chunks = [],
    began = performance.now(),
    value = {
      firstInputMs: null,
      firstOutputByteMs: null,
      streamElapsedMs: null,
      validationMs: null,
      inputBytes: 0,
      outputBytes: 0,
      compressedBytes: 0,
      uncompressedBytes: 0,
      sourcePulls: 0,
      consumerPulls: 0,
      observedMaxInputChunkBytes: 0,
      observedMaxOutputChunkBytes: 0,
      sourceRetired: false,
    };
  const source = (async function* () {
    try {
      for (let offset = 0; offset < sourceBytes.length; offset += 128) {
        const chunk = sourceBytes.subarray(offset, offset + 128);
        value.firstInputMs ??= performance.now() - began;
        value.sourcePulls++;
        value.inputBytes += chunk.length;
        value.observedMaxInputChunkBytes = Math.max(value.observedMaxInputChunkBytes, chunk.length);
        inputDigest.update(chunk);
        yield chunk;
      }
    } finally {
      value.sourceRetired = true;
    }
  })();
  for await (const output of service[operation](source)) {
    const chunk = Buffer.from(output);
    assert.ok(chunk.length > 0 && chunk.length <= 65536);
    value.firstOutputByteMs ??= performance.now() - began;
    value.consumerPulls++;
    value.outputBytes += chunk.length;
    assert.ok(value.outputBytes <= 65536);
    value.observedMaxOutputChunkBytes = Math.max(value.observedMaxOutputChunkBytes, chunk.length);
    outputDigest.update(chunk);
    if (operation === 'gzip') chunks.push(chunk);
  }
  value.streamElapsedMs = performance.now() - began;
  const validationStarted = performance.now();
  assert.equal(inputDigest.digest('hex'), expectedInputDigest);
  value.outputDigest = outputDigest.digest('hex');
  if (operation === 'gzip') {
    assert.deepEqual(gunzipSync(Buffer.concat(chunks), { maxOutputLength: 65536 }), payload);
    value.uncompressedBytes = value.inputBytes;
    value.compressedBytes = value.outputBytes;
  } else {
    assert.equal(value.outputDigest, corpus.plainDigest);
    value.uncompressedBytes = value.outputBytes;
    value.compressedBytes = value.inputBytes;
  }
  value.validationMs = performance.now() - validationStarted;
  assert.equal(value.uncompressedBytes, payload.length);
  assert.equal(value.sourceRetired, true);
  assert.ok(value.streamElapsedMs > 0 && value.firstInputMs >= 0 && value.firstOutputByteMs >= 0);
  value.compressionRatio = value.uncompressedBytes / value.compressedBytes;
  value.inputBytesPerSecond = (value.inputBytes * 1000) / value.streamElapsedMs;
  value.outputBytesPerSecond = (value.outputBytes * 1000) / value.streamElapsedMs;
  return value;
}

export function compressionWorkload(service) {
  const state = observations.get(service);
  assert.ok(state, 'Compression corpus verification must precede workload execution');
  return Object.fromEntries(
    ['gzip', 'gunzip'].map((operation) => [
      operation + '-validated-byte-stream',
      async () => {
        assert.ok(state.calls[operation].length < 512);
        state.calls[operation].push(
          await compressionSmallOperation(service, operation, state.corpus),
        );
        return true;
      },
    ]),
  );
}

function pressureCorpus() {
  // Deterministic fixture bytes have no claimed entropy or cryptographic-key purpose.
  const block = Buffer.alloc(65536);
  for (let offset = 0; offset < block.length; offset += 32)
    hash()
      .update(compressionFixture.marker + ':' + offset)
      .digest()
      .copy(block, offset);
  const bytes = 8388608,
    digest = hash();
  for (let index = 0; index < bytes / block.length; index++) digest.update(block);
  return { block, bytes, digest: digest.digest('hex') };
}

async function producerPlateau(producer, total) {
  let previous = -1,
    stable = 0;
  for (let attempt = 0; attempt < 100; attempt++) {
    // Native zlib jobs can still fill downstream queues after an immediate-turn pause.
    await delay(10);
    assert.equal(producer.retired, false);
    assert.ok(
      producer.pulls < total,
      'The held compression consumer did not backpressure its producer',
    );
    stable = producer.pulls === previous ? stable + 1 : 0;
    previous = producer.pulls;
    if (stable < 3) continue;
    const before = producer.pulls,
      began = performance.now();
    await delay(50);
    assert.equal(producer.retired, false);
    if (producer.pulls !== before) {
      stable = 0;
      previous = producer.pulls;
      continue;
    }
    return {
      producerPullsAtPlateau: before,
      producerPullsAfterHold: producer.pulls,
      observedConsumerHoldMs: performance.now() - began,
      producerFinishedDuringHold: false,
      producerSettleObservations: attempt + 1,
    };
  }
  throw new Error('The compression producer did not reach a bounded pressure plateau');
}

/** Real pressure probes include explicitly named native fixture/validation codec work. */
export async function compressionPressureProbe(service, operation) {
  assert.ok(operation === 'gzip' || operation === 'gunzip');
  const corpus = pressureCorpus(),
    producer = { pulls: 0, bytes: 0, retired: false, firstInputMs: null },
    encodedDigest = hash(),
    plainDigest = hash(),
    ownQueues = { inputBytes: 0, outputBytes: 0 },
    began = performance.now();
  let input,
    output,
    iterator,
    validator,
    validatorTask,
    firstOutputMs,
    firstApiInputMs,
    inputBytes = 0,
    outputBytes = 0,
    decodedValidationBytes = 0,
    observedMaxInputChunkBytes = 0,
    observedMaxOutputChunkBytes = 0,
    fixtureRetired = false;
  const plainSource = (async function* () {
    try {
      for (let index = 0; index < corpus.bytes / 4096; index++) {
        const offset = (index * 4096) % corpus.block.length,
          chunk = corpus.block.subarray(offset, offset + 4096);
        producer.pulls++;
        producer.bytes += chunk.length;
        producer.firstInputMs ??= performance.now() - began;
        yield chunk;
      }
    } finally {
      producer.retired = true;
    }
  })();
  const encodedSource = (async function* () {
    try {
      for await (const chunk of nativeGzip(plainSource, false)) yield chunk;
    } finally {
      fixtureRetired = true;
    }
  })();
  const source = (async function* () {
    try {
      for await (const value of operation === 'gzip' ? plainSource : encodedSource) {
        const chunk = Buffer.from(value);
        inputBytes += chunk.length;
        assert.ok(inputBytes <= (operation === 'gzip' ? corpus.bytes : 16777216));
        assert.ok(chunk.length <= 262144);
        firstApiInputMs ??= performance.now() - began;
        observedMaxInputChunkBytes = Math.max(observedMaxInputChunkBytes, chunk.length);
        if (operation === 'gunzip') encodedDigest.update(chunk);
        yield chunk;
      }
    } finally {
      if (operation === 'gzip') fixtureRetired = true;
    }
  })();
  const sampleQueues = () => {
    if (input) ownQueues.inputBytes = Math.max(ownQueues.inputBytes, input.readableLength);
    if (output) ownQueues.outputBytes = Math.max(ownQueues.outputBytes, output.readableLength);
  };
  try {
    input = Readable.from(source, { objectMode: false, highWaterMark: 4096 });
    output = Readable.from(service[operation](input), { objectMode: false, highWaterMark: 4096 });
    input.on('readable', sampleQueues);
    output.on('readable', sampleQueues);
    iterator = output[Symbol.asyncIterator]();
    let next = await iterator.next();
    assert.equal(next.done, false);
    firstOutputMs = performance.now() - began;
    const pressure = await producerPlateau(producer, corpus.bytes / 4096);
    if (operation === 'gzip') {
      validator = createGunzip({ chunkSize: 16384 });
      validatorTask = (async () => {
        for await (const value of validator) {
          decodedValidationBytes += value.length;
          assert.ok(decodedValidationBytes <= corpus.bytes);
          plainDigest.update(value);
        }
      })();
      void validatorTask.catch(() => undefined);
    }
    do {
      const chunk = Buffer.from(next.value);
      assert.ok(chunk.length > 0 && chunk.length <= 262144);
      outputBytes += chunk.length;
      assert.ok(outputBytes <= (operation === 'gzip' ? 16777216 : corpus.bytes));
      observedMaxOutputChunkBytes = Math.max(observedMaxOutputChunkBytes, chunk.length);
      if (operation === 'gzip') {
        encodedDigest.update(chunk);
        await new Promise((done, reject) =>
          validator.write(chunk, (cause) => (cause ? reject(cause) : done())),
        );
      } else plainDigest.update(chunk);
      sampleQueues();
      next = await iterator.next();
    } while (!next.done);
    const apiStreamElapsedMs = performance.now() - began;
    if (validator) {
      validator.end();
      await validatorTask;
      await finished(validator);
      assert.equal(validator.closed, true);
    }
    await Promise.all([finished(input), finished(output)]);
    assert.equal(producer.retired, true);
    assert.equal(fixtureRetired, true);
    assert.equal(input.closed && output.closed, true);
    assert.equal(producer.bytes, corpus.bytes);
    assert.equal(producer.pulls, corpus.bytes / 4096);
    const uncompressedBytes = operation === 'gzip' ? inputBytes : outputBytes,
      compressedBytes = operation === 'gzip' ? outputBytes : inputBytes;
    assert.equal(uncompressedBytes, corpus.bytes);
    assert.ok(compressedBytes > 0 && compressedBytes <= 16777216);
    assert.ok(uncompressedBytes / compressedBytes <= 100);
    assert.equal(plainDigest.digest('hex'), corpus.digest);
    if (operation === 'gzip') assert.equal(decodedValidationBytes, corpus.bytes);
    return {
      operation,
      uncompressedBytes,
      compressedBytes,
      compressionRatio: uncompressedBytes / compressedBytes,
      encodedDigest: encodedDigest.digest('hex'),
      producerPulls: producer.pulls,
      producerRetired: producer.retired,
      nativeFixtureRetired: operation === 'gunzip' ? fixtureRetired : null,
      nativeValidationDecoderClosed: operation === 'gzip' ? validator.closed : null,
      firstInputMs: firstApiInputMs,
      firstSourceProductionMs: producer.firstInputMs,
      firstOutputMs,
      apiStreamElapsedMs,
      totalElapsedMs: performance.now() - began,
      ...pressure,
      observedMaxInputChunkBytes,
      observedMaxOutputChunkBytes,
      ownReadableQueuePeaks: ownQueues,
      opaqueInternalBufferBytes: null,
      ownStreamsPhysicallyClosed: input.closed && output.closed,
      nativeFixtureOrValidationIncluded:
        operation === 'gzip' ? 'post-pause gunzip validation' : 'upstream native gzip fixture',
    };
  } finally {
    input?.destroy();
    output?.destroy();
    validator?.destroy();
    await iterator?.return?.();
    await Promise.allSettled([input && finished(input), output && finished(output), validatorTask]);
  }
}

export async function compressionObservations(service, { measure, records }) {
  const state = observations.get(service);
  assert.ok(state, 'Compression corpus verification must precede completion');
  if (!measure) {
    assert.equal(records.length, 0);
    return { actualCallbacks: 0, pressureProbesRun: 0, zipTimingSupported: false };
  }
  assert.equal(records.length, 2);
  const streams = {};
  for (const operation of ['gzip', 'gunzip']) {
    const record = records.find(
        (value) => value.operation === operation + '-validated-byte-stream',
      ),
      values = state.calls[operation];
    assert.ok(record);
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.values.length, record.sampleCount);
    assert.equal(values.length, record.sampleCount + record.warmupIterations);
    streams[operation] = {
      actualCallbacks: values.length,
      measurements: values.map((value, index) => ({
        phase: index < record.warmupIterations ? 'warmup' : 'measured',
        ...value,
      })),
    };
  }
  const pressure = [];
  for (const operation of ['gzip', 'gunzip'])
    pressure.push(await compressionPressureProbe(service, operation));
  assert.deepEqual(await collect(service.gunzip(await collect(service.gzip(payload)))), payload);
  const completion = {
    streams,
    pressure,
    postProbeHealthy: true,
    zipTimingSupported: false,
    opaqueInternalBufferBytes: null,
  };
  assert.ok(Buffer.byteLength(JSON.stringify(completion)) < 524288);
  return completion;
}
