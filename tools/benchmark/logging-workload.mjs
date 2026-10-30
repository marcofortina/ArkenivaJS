// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { pino } from 'pino';

export const loggingFixture = Object.freeze({
  message: 'Owned logging workload',
  privateValue: 'pvt-X0',
});
const serviceIdentity = Object.freeze({
  name: 'logging-comparison',
  version: '1.0.0',
  environment: 'test',
});

function recorder(fixture) {
  const state = { rows: 0, bytes: 0, privateOccurrences: 0, last: null };
  const destination = new Writable({
    write(chunk, _encoding, done) {
      try {
        const text = chunk.toString();
        state.bytes += Buffer.byteLength(text);
        if (text.includes(fixture.privateValue)) state.privateOccurrences++;
        for (const line of text.trimEnd().split('\n').filter(Boolean)) {
          state.last = JSON.parse(line);
          state.rows++;
        }
        done();
      } catch (error) {
        done(error);
      }
    },
  });
  return { state, destination };
}
function nativeLogger(logger, capture) {
  const flush = () =>
    new Promise((resolve, reject) => logger.flush((error) => (error ? reject(error) : resolve())));
  return {
    info: (message, fields) => logger.info(fields, message),
    child: (fields) => nativeLogger(logger.child(fields), capture),
    setLevel: (level) => {
      logger.level = level;
    },
    flush,
    async close() {
      await flush();
      capture.destination.destroy();
    },
  };
}

/** One closure belongs to one isolated profile; no logger registry is shared across processes. */
export function createLoggingAdapter() {
  let capture,
    verifiedRows = 0;
  return {
    name: 'logging',
    iterations: 1000,
    warmupIterations: 100,
    native(fixture) {
      capture = recorder(fixture);
      return nativeLogger(
        pino(
          {
            level: 'info',
            base: {
              service: serviceIdentity.name,
              serviceVersion: serviceIdentity.version,
              environment: serviceIdentity.environment,
            },
            timestamp: pino.stdTimeFunctions.isoTime,
            redact: { paths: ['credentials.password'], censor: '[REDACTED]' },
          },
          capture.destination,
        ),
        capture,
      );
    },
    async framework(fixture) {
      capture = recorder(fixture);
      const { COMPONENTS } = await import('@arkenivajs/core');
      return {
        key: COMPONENTS.logger,
        loggingOptions: { destination: capture.destination, ownDestination: true },
      };
    },
    async verify(logger, fixture) {
      const start = capture.state.rows,
        data = {
          operation: 'comparison-operation',
          credentials: { password: fixture.privateValue },
        };
      logger.setLevel('info');
      logger.info(fixture.message, data);
      await logger.flush();
      assert.equal(capture.state.rows, start + 1);
      assert.equal(capture.state.last.credentials.password, '[REDACTED]');
      assert.equal(capture.state.last.msg, fixture.message);
      assert.equal(capture.state.last.service, serviceIdentity.name);
      assert.ok(Number.isFinite(Date.parse(capture.state.last.time)));
      const child = logger.child({ component: 'owned-child' });
      child.info(fixture.message, data);
      await logger.flush();
      assert.equal(capture.state.rows, start + 2);
      assert.equal(capture.state.last.component, 'owned-child');
      logger.setLevel('warn');
      logger.info(fixture.message, data);
      await logger.flush();
      assert.equal(capture.state.rows, start + 2);
      logger.setLevel('info');
      assert.equal(data.credentials.password, fixture.privateValue);
      assert.equal(capture.state.privateOccurrences, 0);
      verifiedRows = capture.state.rows;
      return { checkedWrittenRecords: 2, levelFilterVerified: true, actualRedactionVerified: true };
    },
    workload(logger, fixture) {
      const fields = {
          operation: 'comparison-operation',
          credentials: { password: fixture.privateValue },
        },
        child = logger.child({ component: 'owned-child' });
      return {
        info: () => logger.info(fixture.message, fields),
        childInfo: () => child.info(fixture.message, fields),
      };
    },
    async complete(logger, { records }) {
      await logger.flush();
      assert.equal(capture.state.privateOccurrences, 0);
      const expected =
        verifiedRows +
        records.reduce((sum, row) => sum + row.sampleCount + row.warmupIterations, 0);
      assert.ok(
        capture.state.rows >= expected,
        'Completed logging work must reach the actual destination',
      );
      const stats = logger.stats?.();
      if (stats)
        for (const key of ['dropped', 'failedWrites', 'flushFailures', 'pendingBytes'])
          assert.equal(stats[key], 0);
      return {
        rowsWritten: capture.state.rows,
        bytesWritten: capture.state.bytes,
        privateOccurrences: 0,
        ...(stats ? { frameworkStats: stats } : {}),
      };
    },
    close: (logger) => logger.close(),
  };
}
