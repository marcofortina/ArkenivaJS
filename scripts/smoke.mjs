import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const root = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
assert.equal(root.private, true);
assert.equal(root.type, 'module');
console.log('Workspace ESM smoke passed');
const { KitError } = await import('../packages/core/dist/index.js');
assert.equal(
  new KitError({ code: 'EK_INTERNAL', message: 'private' }).toSafeJSON().code,
  'EK_INTERNAL',
);
console.log('Core error ESM smoke passed');
const { ConfigStore } = await import('../packages/core/dist/support.js');
const config = new ConfigStore(
  { count: 1 },
  {
    schema: {
      type: 'object',
      properties: { count: { type: 'integer' } },
      additionalProperties: false,
    },
    dynamicPaths: ['count'],
  },
);
await config.reload({ count: 2 });
assert.equal(config.require('count'), 2);
assert.ok(Object.isFrozen(config.snapshot()));
console.log('Configuration store smoke passed');
const { createApplication } = await import('../packages/core/dist/index.js');
const application = await createApplication({
  service: { name: 'smoke', version: '1.0.0', environment: 'test' },
});
await application.start();
assert.equal(application.state, 'READY');
await application.stop();
assert.equal(application.state, 'CLOSED');
console.log('Application lifecycle smoke passed');
const { createConfig } = await import('../packages/config/dist/index.js');
const loaded = await createConfig({
  workspace: process.cwd(),
  schema: {
    type: 'object',
    properties: { enabled: { type: 'boolean' } },
    additionalProperties: false,
  },
  yamlText: 'enabled: false',
  environment: {},
  runtime: { enabled: true },
});
assert.equal(loaded.require('enabled'), true);
console.log('Layered configuration smoke passed');
const { Writable } = await import('node:stream');
const { createLogger } = await import('../packages/logging/dist/index.js');
const lines = [];
const log = createLogger({
  service: { name: 'smoke-log', version: '1.0.0', environment: 'test' },
  destination: new Writable({
    write(chunk, encoding, callback) {
      lines.push(String(chunk));
      callback();
    },
  }),
});
log.info('logging smoke', { password: 'fake-private-value' });
await log.flush();
assert.equal(JSON.parse(lines[0]).password, '[REDACTED]');
await log.close();
console.log('Pino logging smoke passed');
const { createDiagnostics } = await import('../packages/diagnostics/dist/index.js');
const diagnostics = createDiagnostics();
const snapshot = diagnostics.snapshot();
assert.equal(snapshot.processId, process.pid);
assert.ok(snapshot.memoryRssBytes > 0);
diagnostics.close();
console.log('Native process diagnostics smoke passed');
