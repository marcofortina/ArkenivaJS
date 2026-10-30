// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { dataCsvPlugin, CSV_CAPABILITY } from '../../dist/index.js';
import type { CsvService } from '../../dist/index.js';

interface Event {
  name: string;
  value: number;
  attributes: Readonly<Record<string, string | number | boolean>>;
}
async function application(mode: 'capture' | 'throw' | 'reject' = 'capture') {
  const events: Event[] = [];
  const record = (
    name: string,
    value: number,
    attributes: Readonly<Record<string, string | number | boolean>> = {},
  ) => {
    if (mode === 'throw') throw new Error('Private observer failure');
    if (mode === 'reject') return Promise.reject(new Error('Private async observer failure'));
    events.push({ name, value, attributes });
  };
  const telemetry: Telemetry = {
    measure: async (_name, work) => work(),
    withSpan: async (_name, work) => work(),
    addCounter: record,
    recordHistogram: record,
    setGauge: record,
    async flush() {},
  };
  const plugin: Plugin = {
    id: 'owned-csv-telemetry',
    version: '1.0.0',
    capabilities: new Set(['telemetry']),
    init(context) {
      context.provide(COMPONENTS.telemetry, telemetry);
    },
    close() {},
  };
  const app = await createApplication({
    service: { name: 'csv-observation-test', version: '1.0.0', environment: 'test' },
    plugins: [
      plugin,
      dataCsvPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 1000 } }),
    ],
  });
  await app.start();
  return { app, csv: app.resolve<CsvService>(CSV_CAPABILITY), events };
}
async function consume<T>(input: AsyncIterable<T>) {
  const result: T[] = [];
  for await (const value of input) result.push(value);
  return result;
}
test('CSV emits exact admitted stream counters without record data or source replay', async () => {
  const { app, csv, events } = await application();
  try {
    let pulls = 0;
    const source = (async function* () {
      pulls++;
      yield Buffer.from('001,private-cell\n');
      await delay(15);
      pulls++;
      yield Buffer.from('002,second\n');
    })();
    const rows = await consume(csv.parse(source));
    assert.equal(pulls, 2);
    const metric = (name: string, operation: string) =>
      events.find(
        (event) => event.name === name && event.attributes['csv.operation'] === operation,
      )!.value;
    assert.equal(metric('csv.rows', 'parse'), 2);
    assert.equal(
      metric('csv.input.bytes', 'parse'),
      Buffer.byteLength('001,private-cell\n002,second\n'),
    );
    assert.equal(
      metric('csv.output.bytes', 'parse'),
      Buffer.byteLength('001private-cell002second'),
    );
    assert.ok(metric('csv.duration.ms', 'parse') >= 10);
    assert.ok(metric('csv.process.rss.peak.bytes', 'parse') > 0);
    const output = Buffer.concat(await consume(csv.stringify(rows)));
    assert.equal(output.toString(), '001,private-cell\n002,second\n');
    assert.equal(metric('csv.rows', 'stringify'), 2);
    assert.equal(metric('csv.output.bytes', 'stringify'), output.length);
    assert.equal(JSON.stringify(events).includes('private-cell'), false);
    assert.ok(
      events.every(
        (event) => Object.keys(event.attributes).sort().join() === 'csv.operation,csv.outcome',
      ),
    );
    assert.ok(events.every((event) => event.attributes['csv.outcome'] === 'ok'));
  } finally {
    await app.stop();
  }
});
test('CSV separates native parse errors from early consumer termination', async () => {
  const { app, csv, events } = await application();
  try {
    await assert.rejects(consume(csv.parse(Buffer.from('"private-unclosed'))), {
      code: 'EK_CSV_PARSE',
    });
    assert.equal(events.find((event) => event.name === 'csv.errors')?.value, 1);
    assert.equal(
      events.find((event) => event.name === 'csv.errors')?.attributes['csv.outcome'],
      'error',
    );
    // Physical admission remains occupied until the failed native pipeline settles.
    await delay(0);
    for await (const row of csv.parse(Buffer.from('001,a\n002,b\n'))) {
      assert.equal(row.rowIndex, 1);
      break;
    }
    assert.equal(events.filter((event) => event.name === 'csv.operations').length, 2);
    assert.equal(
      events.filter((event) => event.name === 'csv.operations')[1]?.attributes['csv.outcome'],
      'cancelled',
    );
    assert.equal(JSON.stringify(events).includes('private-unclosed'), false);
  } finally {
    await app.stop();
  }
});
test('Throwing and asynchronously rejecting CSV observers cannot alter native work', async () => {
  for (const mode of ['throw', 'reject'] as const) {
    const { app, csv } = await application(mode);
    try {
      assert.equal((await consume(csv.parse(Buffer.from('001,a\n')))).length, 1);
      assert.equal(
        Buffer.concat(
          await consume(csv.stringify([{ fields: ['001', 'a'], rowIndex: 1 }])),
        ).toString(),
        '001,a\n',
      );
      await assert.rejects(consume(csv.parse(Buffer.from('"unclosed'))), { code: 'EK_CSV_PARSE' });
      await delay(0);
    } finally {
      await app.stop();
    }
  }
});

test('CSV records writer failure and shutdown of a retained output iterator once', async () => {
  const { app, csv, events } = await application();
  try {
    await assert.rejects(
      consume(csv.stringify([{ fields: ['private-cell'], rowIndex: 1 }], { hasHeader: true })),
      { code: 'EK_CSV_SCHEMA' },
    );
    await delay(0);
    const output = csv.stringify([{ fields: ['001', 'value'], rowIndex: 1 }]);
    assert.equal((await output[Symbol.asyncIterator]().next()).done, false);
    await app.stop();
    await output[Symbol.asyncIterator]().return?.();
    const operations = events.filter((event) => event.name === 'csv.operations');
    assert.equal(operations.length, 2);
    assert.equal(operations[0]?.attributes['csv.outcome'], 'error');
    assert.equal(operations[1]?.attributes['csv.outcome'], 'cancelled');
    assert.equal(events.filter((event) => event.name === 'csv.errors').length, 1);
    assert.equal(JSON.stringify(events).includes('private-cell'), false);
  } finally {
    await app.stop();
  }
});
