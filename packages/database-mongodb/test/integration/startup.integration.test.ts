// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';

test(
  'Real MongoDB startup rejects a wrong TLS identity, an untrusted authority and invalid SCRAM credentials',
  { timeout: 30000 },
  async () => {
    assert.equal(process.env.ARKENIVA_MONGODB_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVA_MONGODB_URL);
    assert.ok(process.env.ARKENIVA_MONGODB_WRONG_SAN_URL);
    const untrusted = new URL(process.env.ARKENIVA_MONGODB_URL),
      unauthenticated = new URL(process.env.ARKENIVA_MONGODB_URL);
    untrusted.searchParams.delete('tlsCAFile');
    unauthenticated.password = 'disposable-invalid-password';
    const variable = 'ARKENIVA_MONGODB_STARTUP_NEGATIVE',
      previous = process.env[variable];
    try {
      for (const url of [
        process.env.ARKENIVA_MONGODB_WRONG_SAN_URL,
        untrusted.href,
        unauthenticated.href,
      ]) {
        process.env[variable] = url;
        const app = await createApplication({
          service: { name: 'mongodb-startup-negative', version: '1.0.0', environment: 'test' },
          plugins: [mongodbPlugin()],
          databases: { documents: { driver: 'mongodb', connectionStringEnv: variable } },
        });
        const mongo = app.mongo!;
        try {
          await assert.rejects(app.start());
          assert.equal(app.state, 'CLOSED');
          assert.throws(() => mongo.native(), { code: 'EK_RESOURCE_CLOSED' });
        } finally {
          await app.stop();
        }
      }
    } finally {
      if (previous === undefined) delete process.env[variable];
      else process.env[variable] = previous;
    }
  },
);
