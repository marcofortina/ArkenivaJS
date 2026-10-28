// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { securityStateFixture } from './security-state-fixture.js';
import { fixture } from './saml-fixture.js';

test(
  'Separate SAML processes with independent verified PostgreSQL pools accept exactly one signed response',
  { timeout: 20000 },
  async () => {
    const backend = await securityStateFixture(),
      f = await fixture('redirect', backend.store),
      children: ReturnType<typeof fork>[] = [];
    const exits: Promise<unknown>[] = [];
    try {
      const request = await f.service.beginLogin({ returnPath: '/app' }),
        response = f.response(request.requestId);
      const {
        secretProvider: _secrets,
        replayStore: _state,
        authority: _authority,
        ...settings
      } = f.settings;
      void _secrets;
      void _state;
      void _authority;
      const key = await readFile(join(f.directory, 'sp.key'), 'utf8'),
        certificate = await readFile(join(f.directory, 'sp.pem'), 'utf8');
      const workers = Array.from({ length: 2 }, () => {
        let failureCodes = '';
        const child = fork(new URL('./saml-worker.js', import.meta.url), [], {
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
          env: {
            NODE_ENV: 'test',
            DATABASE_URL: process.env.DATABASE_URL!,
            ARKENIVA_POSTGRES_DISPOSABLE: process.env.ARKENIVA_POSTGRES_DISPOSABLE!,
          },
        });
        children.push(child);
        exits.push(
          once(child, 'exit').then(([code]) => {
            assert.equal(
              code,
              0,
              'The independent SAML process must close cleanly: ' + failureCodes,
            );
          }),
        );
        const ready = new Promise<void>((resolve, reject) => {
          child.on('message', (message) => {
            const value = message as { type: string; codes?: string[] };
            if (value.type === 'ready') resolve();
            if (value.type === 'failed') {
              failureCodes = (value.codes ?? []).join(',');
              reject(new Error('The independent SAML process failed startup: ' + failureCodes));
            }
          });
          child.once('error', reject);
          child.once('exit', (code) => {
            if (code !== 0) reject(new Error('The independent SAML process exited'));
          });
        });
        const result = new Promise<string>((resolve, reject) => {
          child.on('message', (message) => {
            const value = message as { type: string; result: string };
            if (value.type === 'result') resolve(value.result);
            if (value.type === 'failed') reject(new Error('The independent SAML process failed'));
          });
          child.once('error', reject);
          child.once('exit', (code) => {
            if (code !== 0) reject(new Error('The independent SAML process exited'));
          });
        });
        void result.catch(() => undefined);
        // The owned IPC channel carries ephemeral signing material without arguments, environment or output.
        child.send({ type: 'start', schema: backend.schema, settings, key, certificate });
        return { child, ready, result };
      });
      await Promise.all(workers.map((worker) => worker.ready));
      for (const worker of workers)
        worker.child.send({ type: 'consume', requestId: request.requestId, response });
      assert.deepEqual((await Promise.all(workers.map((worker) => worker.result))).sort(), [
        'EK_SAML_REPLAY',
        'accepted',
      ]);
    } finally {
      for (const child of children) if (child.connected) child.send({ type: 'close' });
      const timer = setTimeout(() => {
        for (const child of children) if (child.exitCode === null) child.kill('SIGTERM');
      }, 5000);
      timer.unref();
      try {
        await Promise.all(exits);
      } finally {
        clearTimeout(timer);
        await f.close();
        await backend.close();
      }
    }
  },
);
