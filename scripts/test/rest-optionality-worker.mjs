// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { Writable } from 'node:stream';

const packages = [
  '@arkenivajs/graphql',
  'graphql',
  'mercurius',
  'graphiql',
  'graphql-ws',
  'react',
  'react-dom',
];
const firstParty = new URL('../../packages/graphql/', import.meta.url).href;
const blockedMessage = 'The REST-only fixture attempted to load an optional GraphQL module';
let blocked = 0;
const reject = () => {
  blocked++;
  throw new Error(blockedMessage);
};

// Install the guard before dynamically importing any framework package, including CJS dependencies.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (
      packages.some((name) => specifier === name || specifier.startsWith(name + '/')) ||
      specifier.startsWith(firstParty)
    )
      reject();
    const result = nextResolve(specifier, context);
    if (
      result.url.startsWith(firstParty) ||
      packages.some((name) => result.url.includes('/node_modules/' + name + '/'))
    )
      reject();
    return result;
  },
});

const sink = new Writable({
  write(_chunk, _encoding, done) {
    done();
  },
});
let app;
try {
  const { createApplication } = await import('../../packages/core/dist/index.js');
  const { apiPlugin } = await import('../../packages/api/dist/index.js');
  const { loggingPlugin } = await import('../../packages/logging/dist/index.js');
  app = await createApplication({
    service: { name: 'rest-optionality-test', version: '1.0.0', environment: 'test' },
    http: { host: '127.0.0.1', port: 0 },
    plugins: [loggingPlugin({ destination: sink }), apiPlugin()],
  });
  app.api.get('/rest-only', {
    auth: { required: false },
    schema: {
      response: {
        type: 'object',
        properties: { ok: { type: 'boolean' } },
        required: ['ok'],
        additionalProperties: false,
      },
    },
    handler: () => ({ ok: true }),
  });
  await app.start();
  const origin = app.api.address();
  assert.equal(new URL(origin).hostname, '127.0.0.1');
  const response = await globalThis.fetch(origin + '/rest-only');
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
  const absent = await globalThis.fetch(origin + '/graphql', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"query":"{ ping }"}',
  });
  assert.equal(absent.status, 404);
  await absent.arrayBuffer();
  await app.stop();
  assert.equal(app.state, 'CLOSED');
  assert.equal(blocked, 0);
  // Both controls must fail through the active guard, rather than missing-package resolution.
  const denied = (error) => error instanceof Error && error.message === blockedMessage;
  await assert.rejects(import('graphql'), denied);
  await assert.rejects(import('../../packages/graphql/dist/index.js'), denied);
  assert.equal(blocked, 2);
  console.log(
    JSON.stringify({
      restStatus: 200,
      absentGraphqlStatus: 404,
      optionalImports: 0,
      activeNegativeControls: 2,
      closed: true,
    }),
  );
} finally {
  await app?.stop();
  sink.destroy();
}
