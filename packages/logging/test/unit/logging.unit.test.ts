import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { createLogger, loggingPlugin } from '@arkenivajs/logging';
import { KitError, createApplication } from '@arkenivajs/core';
import type { LogLevel } from '@arkenivajs/logging';

const service = { name: 'logging-test', version: '1.0.0', environment: 'test' } as const;
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function capture() {
  const lines: string[] = [];
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(String(chunk));
      callback();
    },
  });
  return { lines, destination };
}

test('EK-LOG-001 Pino emits JSON levels, timestamps, immutable child and protected context', async () => {
  const { lines, destination } = capture();
  const logger = createLogger({ service, destination, level: 'trace' });
  const child = logger.child({ component: 'storage', traceId: 'trace-a', service: 'spoofed' });
  for (const level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal'] as const)
    child[level]('operation', { traceId: 'spoofed', level: 999, time: 'wrong' });
  await logger.flush();
  const values = lines.map((line) => JSON.parse(line));
  assert.deepEqual(
    values.map((value) => value.level),
    [10, 20, 30, 40, 50, 60],
  );
  for (const value of values) {
    assert.equal(value.service, service.name);
    assert.equal(value.traceId, 'trace-a');
    assert.equal(value.component, 'storage');
    assert.ok(Number.isFinite(Date.parse(value.time)));
  }
  child.setLevel('silent');
  child.info('hidden');
  assert.equal(lines.length, 6);
  assert.throws(() => logger.setLevel('invalid' as LogLevel), code('EK_CONFIG_INVALID'));
  assert.throws(() => logger.info(1 as never), code('EK_CONFIG_INVALID'));
  assert.throws(() => logger.child(null as never), code('EK_CONFIG_INVALID'));
  await logger.close();
  await logger.close();
  assert.throws(() => logger.info('closed'), code('EK_RESOURCE_CLOSED'));
  await assert.rejects(logger.flush(), code('EK_RESOURCE_CLOSED'));
});

test('EK-LOG-001 nested credentials, error causes, cycles and accessors are safe before transport', async () => {
  const { lines, destination } = capture();
  const logger = createLogger({
    service,
    destination,
    redactPaths: ['custom.value'],
    redactValues: ['fake-inline-secret'],
  });
  const circular: Record<string, unknown> = { password: 'fake-password' };
  circular.self = circular;
  const fields = {
    nested: {
      authorization: 'Bearer fake-token',
      cookie: 'fake-cookie',
      token: 'fake-token',
      clientSecret: 'fake-secret',
    },
    circular,
    custom: { value: 'fake-custom' },
    error: new KitError({
      code: 'EK_INTERNAL',
      message: 'fake-error-message',
      cause: new Error('fake-cause'),
    }),
    native: new Error('fake-native'),
    binary: Buffer.from('fake-binary'),
    count: 42n,
    get getter() {
      throw new Error('getter executed');
    },
    function: () => 1,
  };
  logger.error(
    'password=fake-password Bearer fake-token https://user:fake-url@example.invalid fake-inline-secret',
    fields,
  );
  await logger.flush();
  const output = lines.join('');
  assert.ok(!output.includes('fake-'));
  assert.ok(!output.includes('getter executed'));
  assert.ok(output.includes('[Circular]'));
  assert.ok(output.includes('[REDACTED]'));
  await logger.close();
});

test('EK-LOG-001 asynchronous log scopes remain isolated across concurrent operations', async () => {
  const { lines, destination } = capture();
  const logger = createLogger({ service, destination });
  await Promise.all(
    ['a', 'b'].map((requestId) =>
      logger.run({ requestId }, async () => {
        await delay(requestId === 'a' ? 5 : 1);
        logger.info('scoped', { requestId: 'spoofed' });
      }),
    ),
  );
  logger.info('outside');
  await logger.flush();
  const values = lines.map((line) => JSON.parse(line));
  assert.deepEqual(
    values
      .slice(0, 2)
      .map((value) => value.requestId)
      .sort(),
    ['a', 'b'],
  );
  assert.equal(values[2]?.requestId, undefined);
  assert.throws(() => logger.run({}, undefined as never), code('EK_CONFIG_INVALID'));
  await logger.close();
});

test('EK-LOG-001 flush acknowledges writes, honors abort and deadline, and bounds queued bytes', async () => {
  let release!: () => void;
  const diagnostics: unknown[] = [];
  const destination = new Writable({
    write(_chunk, _encoding, callback) {
      release = () => callback();
    },
  });
  const logger = createLogger({
    service,
    destination,
    bufferLimitBytes: 512,
    onDiagnostic: (event) => diagnostics.push(event),
  });
  logger.info('pending');
  for (let i = 0; i < 20; i++) logger.info('overflow');
  assert.ok(logger.stats().dropped > 0);
  assert.ok(logger.stats().pendingBytes <= 512);
  await assert.rejects(logger.flush({ timeoutMs: 5 }), code('EK_TIMEOUT'));
  await assert.rejects(logger.flush({ signal: AbortSignal.abort() }), code('EK_ABORTED'));
  // Release each queued write; the writable can start another buffered chunk synchronously.
  while (logger.stats().pendingBytes) {
    release();
    await delay(1);
  }
  await logger.flush();
  assert.equal(diagnostics.length, 1);
  assert.ok(Object.isFrozen(logger.stats()));
  await logger.close();
});

test('EK-LOG-001 destination errors never disclose native messages and reject flush', async () => {
  const diagnostics: unknown[] = [];
  const destination = new Writable({
    write(_chunk, _encoding, callback) {
      callback(new Error('fake-transport-secret'));
    },
  });
  const logger = createLogger({
    service,
    destination,
    onDiagnostic: (event) => diagnostics.push(event),
  });
  logger.info('failed write');
  await delay(1);
  logger.info('dropped after failure');
  await assert.rejects(logger.flush(), code('EK_BACKEND_UNAVAILABLE'));
  assert.equal(logger.stats().failedWrites, 1);
  assert.equal(logger.stats().dropped, 1);
  assert.equal(diagnostics.length, 1);
  assert.ok(!JSON.stringify(diagnostics).includes('fake-'));
  await assert.rejects(logger.close(), code('EK_BACKEND_UNAVAILABLE'));
  await logger.close();
});

test('EK-LOG-001 invalid levels, destinations, redaction settings and capacity reject', () => {
  for (const options of [
    undefined,
    { service, level: 'invalid' },
    { service, bufferLimitBytes: 0 },
    { service, redactValues: [''] },
    { service: {} },
    { service, destination: {} },
    { service, redactPaths: ['[invalid'] },
  ])
    assert.throws(() => createLogger(options as never), code('EK_CONFIG_INVALID'));
});

test('EK-LOG-001 application logging initializes before ordinary plugins and flushes on stop', async () => {
  const { lines, destination } = capture();
  const app = await createApplication({
    service,
    plugins: [
      {
        id: 'consumer',
        version: '1.0.0',
        capabilities: new Set(),
        init(ctx) {
          ctx.logger.info('plugin ready');
        },
        close(ctx) {
          ctx.logger.info('plugin stopped');
        },
      },
      loggingPlugin({ destination }),
    ],
  });
  await app.start();
  app.logger.info('application ready');
  await app.stop();
  assert.equal(lines.length, 3);
  assert.deepEqual(
    lines.map((line) => JSON.parse(line).msg),
    ['plugin ready', 'application ready', 'plugin stopped'],
  );
});

test('EK-LOG-001 one plugin factory keeps application logger instances independent', async () => {
  const { lines, destination } = capture();
  const shared = loggingPlugin({ destination });
  const first = await createApplication({ service, plugins: [shared] });
  const second = await createApplication({ service, plugins: [shared] });
  await first.start();
  await second.start();
  await first.stop();
  second.logger.info('second remains open');
  await second.stop();
  assert.equal(JSON.parse(lines[0]!).msg, 'second remains open');
});

test('EK-LOG-001 owned destinations close once and concurrent close shares completion', async () => {
  const { destination } = capture();
  const logger = createLogger({ service, destination, ownDestination: true });
  logger.info('owned');
  const first = logger.close();
  assert.equal(first, logger.close());
  await first;
  await delay(1);
  assert.equal(destination.destroyed, true);
  assert.equal(destination.listenerCount('error'), 0);
});

test('EK-LOG-001 synchronous transport failure and failing diagnostic callbacks remain sanitized', async () => {
  const { destination } = capture();
  destination.write = (() => {
    throw new Error('fake-synchronous-secret');
  }) as Writable['write'];
  const logger = createLogger({
    service,
    destination,
    onDiagnostic() {
      throw new Error('fake-diagnostic-secret');
    },
  });
  logger.info('attempt');
  assert.equal(logger.stats().failedWrites, 1);
  await assert.rejects(logger.close(), code('EK_BACKEND_UNAVAILABLE'));
});
