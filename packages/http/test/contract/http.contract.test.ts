import test from 'node:test';
import assert from 'node:assert/strict';
import { createHttpClient, DEFAULT_HTTP_TIMEOUT_MS } from '@arkenivajs/http';
import type { OutboundHttpClient } from '@arkenivajs/core';

test('Outbound HTTP public entry implements the typed client and exact default deadline', async () => {
  const managed = createHttpClient({ allowedOrigins: [] });
  const client: OutboundHttpClient = managed;
  assert.equal(DEFAULT_HTTP_TIMEOUT_MS, 10_000);
  assert.equal(typeof client.request, 'function');
  assert.equal(typeof client.get, 'function');
  assert.equal(typeof client.post, 'function');
  await managed.close();
});
