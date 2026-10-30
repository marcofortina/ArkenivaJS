// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { pipeline, finished } from 'node:stream/promises';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { setImmediate as nextTurn, setTimeout as delay } from 'node:timers/promises';
import { stringify as stringifySync } from 'csv-stringify/sync';
import { parse } from 'csv-parse';
import { stringify } from 'csv-stringify';

export const csvFixture = Object.freeze({ marker: 'owned-csv-fixture' });
export const csvSettings = Object.freeze({
  defaults: Object.freeze({}),
  policy: Object.freeze({ maxConcurrent: 1, timeoutMs: 5000 }),
});
export const csvFields = Object.freeze([
  Object.freeze(['001', csvFixture.marker, 'line\nnext', '"quoted"', 'λ😀']),
  Object.freeze(['002', 'comma,value', '', 'tab\tvalue', 'last']),
]);
export const csvRows = () => csvFields.map((fields, index) => ({ fields, rowIndex: index + 1 }));
export async function collectCsvBytes(input) {
  const chunks = [];
  for await (const chunk of input) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}
export async function collectCsvFields(input) {
  const rows = [];
  for await (const row of input) {
    assert.equal(row.rowIndex, rows.length + 1);
    assert.ok(row.fields.every((value) => typeof value === 'string'));
    rows.push([...row.fields]);
  }
  return rows;
}
/** Native stream adapters cover a fixed valid corpus without framework policy emulation. */
export function nativeCsv() {
  return {
    async *parse(input, options = {}) {
      const source = Readable.from(input instanceof Uint8Array ? [input] : input, {
          objectMode: false,
          highWaterMark: 16384,
        }),
        codec = parse({ delimiter: options.delimiter ?? ',', bom: true, cast: false }),
        task = pipeline(source, codec);
      void task.catch(() => undefined);
      let rowIndex = 0;
      try {
        for await (const fields of codec) yield { fields, rowIndex: ++rowIndex };
        await task;
      } finally {
        source.destroy();
        codec.destroy();
      }
    },
    async *stringify(rows, options = {}) {
      const source = Readable.from(
          (async function* () {
            for await (const row of rows) yield row.fields;
          })(),
        ),
        codec = stringify({
          delimiter: options.delimiter ?? ',',
          bom: options.outputBom ?? false,
          record_delimiter: '\n',
        }),
        task = pipeline(source, codec);
      void task.catch(() => undefined);
      try {
        for await (const chunk of codec) yield chunk;
        await task;
      } finally {
        source.destroy();
        codec.destroy();
      }
    },
  };
}
const observations = new WeakMap();

export async function verifyCsv(service) {
  for (const delimiter of [',', '\t', ';']) {
    const bytes = await collectCsvBytes(
        service.stringify(csvRows(), { delimiter, outputBom: true }),
      ),
      before = Buffer.from(bytes);
    assert.deepEqual([...bytes.subarray(0, 3)], [239, 187, 191]);
    let pulls = 0;
    const input = (async function* () {
      for (let index = 0; index < bytes.length; index++) {
        pulls++;
        yield bytes.subarray(index, index + 1);
      }
    })();
    assert.deepEqual(await collectCsvFields(service.parse(input, { delimiter })), csvFields);
    assert.equal(pulls, bytes.length);
    assert.deepEqual(bytes, before);
  }
  assert.deepEqual(await collectCsvFields(service.parse(new Uint8Array())), []);
  assert.equal((await collectCsvBytes(service.stringify([]))).length, 0);
  observations.set(service, { corpus: csvSmallCorpus(), calls: { parse: [], stringify: [] } });
  return { checkedDelimiters: 3, checkedRows: 6, completedStreams: true, textOnly: true };
}

const hash = () => createHash('sha256');
const digestRow = (digest, rowIndex, fields) =>
  digest.update(JSON.stringify([rowIndex, ...fields]) + '\n');
const fieldBytes = (fields) => fields.reduce((sum, value) => sum + Buffer.byteLength(value), 0);

export function csvSmallCorpus() {
  const rows = Array.from({ length: 256 }, (_, index) => [...csvFields[index % csvFields.length]]),
    bytes = Buffer.from(stringifySync(rows, { bom: true, record_delimiter: '\n' })),
    expectedRows = hash();
  for (let index = 0; index < rows.length; index++) digestRow(expectedRows, index + 1, rows[index]);
  assert.ok(bytes.length < 65536);
  return {
    rows: rows.length,
    bytes,
    byteDigest: hash().update(bytes).digest('hex'),
    rowDigest: expectedRows.digest('hex'),
    fieldBytes: rows.reduce((sum, fields) => sum + fieldBytes(fields), 0),
  };
}

function streamMetrics() {
  return {
    firstInputMs: null,
    firstOutputByteMs: null,
    firstOutputDataByteMs: null,
    firstOutputRowMs: null,
    elapsedMs: null,
    rows: 0,
    encodedInputBytes: 0,
    encodedOutputBytes: 0,
    fieldUtf8Bytes: 0,
    sourcePulls: 0,
    consumerPulls: 0,
    observedMaxInputChunkBytes: 0,
    observedMaxOutputChunkBytes: 0,
    sourceRetired: false,
    digest: null,
  };
}

/** Observe actual stream boundaries, not hidden codec allocations or completed-stream estimates. */
export async function csvSmallOperation(service, operation, corpus = csvSmallCorpus()) {
  assert.ok(operation === 'parse' || operation === 'stringify');
  const metrics = streamMetrics(),
    started = performance.now(),
    digest = hash();
  const since = () => performance.now() - started;
  if (operation === 'parse') {
    const source = (async function* () {
      try {
        for (let offset = 0; offset < corpus.bytes.length; offset += 1024) {
          const chunk = corpus.bytes.subarray(offset, offset + 1024);
          metrics.firstInputMs ??= since();
          metrics.sourcePulls++;
          metrics.encodedInputBytes += chunk.length;
          metrics.observedMaxInputChunkBytes = Math.max(
            metrics.observedMaxInputChunkBytes,
            chunk.length,
          );
          yield chunk;
        }
      } finally {
        metrics.sourceRetired = true;
      }
    })();
    for await (const row of service.parse(source)) {
      metrics.firstOutputRowMs ??= since();
      metrics.consumerPulls++;
      metrics.rows++;
      assert.equal(row.rowIndex, metrics.rows);
      assert.deepEqual([...row.fields], csvFields[(metrics.rows - 1) % csvFields.length]);
      metrics.fieldUtf8Bytes += fieldBytes(row.fields);
      digestRow(digest, row.rowIndex, row.fields);
    }
    metrics.digest = digest.digest('hex');
    assert.equal(metrics.encodedInputBytes, corpus.bytes.length);
    assert.equal(metrics.digest, corpus.rowDigest);
  } else {
    const source = (async function* () {
      try {
        for (let index = 0; index < corpus.rows; index++) {
          const fields = csvFields[index % csvFields.length];
          metrics.firstInputMs ??= since();
          metrics.sourcePulls++;
          metrics.rows++;
          metrics.fieldUtf8Bytes += fieldBytes(fields);
          yield { fields, rowIndex: index + 1 };
        }
      } finally {
        metrics.sourceRetired = true;
      }
    })();
    for await (const value of service.stringify(source, { outputBom: true })) {
      const chunk = Buffer.from(value);
      assert.ok(chunk.length > 0 && chunk.length <= 65536);
      metrics.firstOutputByteMs ??= since();
      if (metrics.encodedOutputBytes + chunk.length > 3) metrics.firstOutputDataByteMs ??= since();
      metrics.consumerPulls++;
      metrics.encodedOutputBytes += chunk.length;
      metrics.observedMaxOutputChunkBytes = Math.max(
        metrics.observedMaxOutputChunkBytes,
        chunk.length,
      );
      digest.update(chunk);
    }
    metrics.digest = digest.digest('hex');
    assert.equal(metrics.encodedOutputBytes, corpus.bytes.length);
    assert.equal(metrics.digest, corpus.byteDigest);
  }
  metrics.elapsedMs = since();
  assert.equal(metrics.rows, corpus.rows);
  assert.equal(metrics.fieldUtf8Bytes, corpus.fieldBytes);
  assert.equal(metrics.sourceRetired, true);
  assert.ok(metrics.elapsedMs > 0 && Number.isFinite(metrics.elapsedMs));
  assert.ok(Number.isFinite(metrics.firstInputMs) && metrics.firstInputMs >= 0);
  assert.ok(
    Number.isFinite(operation === 'parse' ? metrics.firstOutputRowMs : metrics.firstOutputByteMs),
  );
  metrics.rowsPerSecond = (metrics.rows * 1000) / metrics.elapsedMs;
  metrics.encodedBytesPerSecond =
    ((metrics.encodedInputBytes + metrics.encodedOutputBytes) * 1000) / metrics.elapsedMs;
  return metrics;
}

export function csvWorkload(service) {
  const state = observations.get(service);
  assert.ok(state, 'CSV corpus verification must precede workload execution');
  return Object.fromEntries(
    ['parse', 'stringify'].map((operation) => [
      operation + '-stream-256-rows',
      async () => {
        assert.ok(state.calls[operation].length < 512);
        state.calls[operation].push(await csvSmallOperation(service, operation, state.corpus));
        return true;
      },
    ]),
  );
}

function pressureCorpus() {
  const fields = ['001', csvFixture.marker, 'quoted,\n"field"', 'λ😀', ''];
  const overhead = Buffer.byteLength(stringifySync([fields], { record_delimiter: '\n' }));
  fields[4] = 'x'.repeat(1024 - overhead);
  const row = Buffer.from(stringifySync([fields], { record_delimiter: '\n' }));
  assert.equal(row.length, 1024);
  const rows = 8192,
    bytes = rows * row.length,
    byteDigest = hash(),
    rowDigest = hash();
  for (let index = 0; index < rows; index++) {
    byteDigest.update(row);
    digestRow(rowDigest, index + 1, fields);
  }
  return {
    fields,
    row,
    rows,
    bytes,
    byteDigest: byteDigest.digest('hex'),
    rowDigest: rowDigest.digest('hex'),
  };
}

/** Source is ungated: a plateau before EOF must result from actual downstream suspension. */
async function stalledProducer(producer, total) {
  let previous = -1,
    stable = 0;
  for (let attempt = 0; attempt < 100; attempt++) {
    await nextTurn();
    assert.equal(producer.retired, false);
    assert.ok(producer.pulls < total, 'The paused CSV consumer did not backpressure its producer');
    stable = producer.pulls === previous ? stable + 1 : 0;
    previous = producer.pulls;
    if (stable >= 3) break;
  }
  assert.ok(stable >= 3, 'The CSV producer did not reach a bounded pressure plateau');
  const before = producer.pulls,
    began = performance.now();
  await delay(50);
  assert.equal(producer.retired, false);
  assert.equal(producer.pulls, before, 'The CSV producer advanced while its consumer was held');
  return {
    producerPullsAtPlateau: before,
    producerPullsAfterHold: producer.pulls,
    observedConsumerHoldMs: performance.now() - began,
    producerFinishedDuringHold: false,
  };
}

/** Large lazy probe is separate from Tinybench samples; queue observations cover owned wrappers only. */
export async function csvPressureProbe(service, operation) {
  assert.ok(operation === 'parse' || operation === 'stringify');
  const corpus = pressureCorpus(),
    producer = { pulls: 0, bytes: 0, firstInputMs: null, retired: false },
    digest = hash(),
    ownQueues = { inputBytes: 0, inputRows: 0, outputBytes: 0, outputRows: 0 },
    started = performance.now();
  let rows = 0,
    bytes = 0,
    peakInputChunkBytes = 0,
    peakOutputChunkBytes = 0,
    input,
    output,
    iterator,
    pressure,
    firstOutputMs;
  const sampleQueues = () => {
    if (input) {
      const key = input.readableObjectMode ? 'inputRows' : 'inputBytes';
      ownQueues[key] = Math.max(ownQueues[key], input.readableLength);
    }
    if (output) {
      const key = output.readableObjectMode ? 'outputRows' : 'outputBytes';
      ownQueues[key] = Math.max(ownQueues[key], output.readableLength);
    }
  };
  const source =
    operation === 'parse'
      ? (async function* () {
          const chunk = Buffer.concat([corpus.row, corpus.row, corpus.row, corpus.row]);
          try {
            for (let index = 0; index < corpus.rows / 4; index++) {
              producer.pulls++;
              producer.firstInputMs ??= performance.now() - started;
              producer.bytes += chunk.length;
              peakInputChunkBytes = Math.max(peakInputChunkBytes, chunk.length);
              yield chunk;
            }
          } finally {
            producer.retired = true;
          }
        })()
      : (async function* () {
          try {
            for (let index = 0; index < corpus.rows; index++) {
              producer.pulls++;
              producer.firstInputMs ??= performance.now() - started;
              producer.bytes += fieldBytes(corpus.fields);
              yield { fields: corpus.fields, rowIndex: index + 1 };
            }
          } finally {
            producer.retired = true;
          }
        })();
  try {
    input = Readable.from(source, {
      objectMode: operation === 'stringify',
      highWaterMark: operation === 'parse' ? 4096 : 1,
    });
    output = Readable.from(
      operation === 'parse' ? service.parse(input) : service.stringify(input),
      { objectMode: operation === 'parse', highWaterMark: operation === 'parse' ? 1 : 4096 },
    );
    input.on('readable', sampleQueues);
    output.on('readable', sampleQueues);
    iterator = output[Symbol.asyncIterator]();
    let next = await iterator.next();
    assert.equal(next.done, false);
    firstOutputMs = performance.now() - started;
    sampleQueues();
    pressure = await stalledProducer(
      producer,
      operation === 'parse' ? corpus.rows / 4 : corpus.rows,
    );
    do {
      if (operation === 'parse') {
        rows++;
        assert.equal(next.value.rowIndex, rows);
        assert.deepEqual([...next.value.fields], corpus.fields);
        digestRow(digest, rows, next.value.fields);
      } else {
        const chunk = Buffer.from(next.value);
        assert.ok(chunk.length > 0 && chunk.length <= 262144);
        bytes += chunk.length;
        peakOutputChunkBytes = Math.max(peakOutputChunkBytes, chunk.length);
        digest.update(chunk);
      }
      sampleQueues();
      next = await iterator.next();
    } while (!next.done);
    await Promise.all([finished(input), finished(output)]);
    assert.equal(producer.retired, true);
    assert.equal(input.closed && output.closed, true);
    if (operation === 'parse') assert.equal(producer.bytes, corpus.bytes);
    assert.equal(producer.pulls, operation === 'parse' ? corpus.rows / 4 : corpus.rows);
    assert.equal(
      digest.digest('hex'),
      operation === 'parse' ? corpus.rowDigest : corpus.byteDigest,
    );
    assert.equal(
      operation === 'parse' ? rows : bytes,
      operation === 'parse' ? corpus.rows : corpus.bytes,
    );
    return {
      operation,
      encodedCorpusBytes: corpus.bytes,
      corpusRows: corpus.rows,
      completedRows: operation === 'parse' ? rows : producer.pulls,
      completedEncodedBytes: operation === 'parse' ? producer.bytes : bytes,
      observedEncodedInputBytes: operation === 'parse' ? producer.bytes : null,
      observedEncodedOutputBytes: operation === 'stringify' ? bytes : null,
      observedInputFieldUtf8Bytes: operation === 'stringify' ? producer.bytes : null,
      producerPulls: producer.pulls,
      producerRetired: producer.retired,
      firstInputMs: producer.firstInputMs,
      firstOutputKind: operation === 'parse' ? 'row' : 'byte',
      firstOutputMs,
      totalElapsedMs: performance.now() - started,
      ...pressure,
      observedMaxInputChunkBytes: peakInputChunkBytes,
      observedMaxOutputChunkBytes: peakOutputChunkBytes,
      ownReadableQueuePeaks: ownQueues,
      opaqueInternalBufferBytes: null,
      ownStreamsPhysicallyClosed: input.closed && output.closed,
    };
  } finally {
    input?.destroy();
    output?.destroy();
    await iterator?.return?.();
    await Promise.allSettled([input && finished(input), output && finished(output)]);
  }
}

export async function csvObservations(service, { measure, records }) {
  const state = observations.get(service);
  assert.ok(state, 'CSV corpus verification must precede completion');
  const streams = {};
  if (measure) {
    assert.equal(records.length, 2);
    for (const operation of ['parse', 'stringify']) {
      const record = records.find((value) => value.operation === operation + '-stream-256-rows'),
        values = state.calls[operation];
      assert.ok(record);
      assert.equal(record.sampleCount, 100);
      assert.equal(record.warmupIterations, 20);
      assert.equal(record.rawLatency.values.length, record.sampleCount);
      assert.equal(values.length, record.sampleCount + record.warmupIterations);
      streams[operation] = {
        actualCallbacks: values.length,
        measuredCallbacks: record.sampleCount,
        warmupCallbacks: record.warmupIterations,
        measurements: values.map((value, index) => ({
          phase: index < record.warmupIterations ? 'warmup' : 'measured',
          ...value,
        })),
      };
    }
    const pressure = [];
    for (const operation of ['parse', 'stringify'])
      pressure.push(await csvPressureProbe(service, operation));
    // Fresh tiny operations verify that physical completion released the maxConcurrent=1 lane.
    assert.deepEqual(
      await collectCsvFields(service.parse(await collectCsvBytes(service.stringify(csvRows())))),
      csvFields,
    );
    const completion = {
      streams,
      pressure,
      postProbeHealthy: true,
      opaqueInternalBufferBytes: null,
    };
    assert.ok(Buffer.byteLength(JSON.stringify(completion)) < 524288);
    return completion;
  }
  assert.equal(records.length, 0);
  assert.equal(state.calls.parse.length + state.calls.stringify.length, 0);
  return { actualCallbacks: 0, pressureProbesRun: 0 };
}
