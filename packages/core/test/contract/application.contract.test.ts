import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import type { Application, ApplicationOptions } from '@arkenivajs/core';
const create: (options: ApplicationOptions) => Promise<Application> = createApplication;
test('Application lifecycle exposes stable states through the public ESM entry point', async () => {
  const app = await create({
    service: { name: 'contract', version: '1.0.0', environment: 'test' },
  });
  await app.start();
  assert.equal(app.state, 'READY');
  await app.stop();
  assert.equal(app.state, 'CLOSED');
});
