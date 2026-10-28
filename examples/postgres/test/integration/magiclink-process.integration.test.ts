// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '@arkenivajs/security-magiclink';
import type { MagicLinkService } from '@arkenivajs/security-magiclink';
import { apiKeyFixture } from './api-key-fixture.js';
import { nativeFixtureHmac } from '../magiclink-unit-fixture.js';

test(
  'Separate Node processes with independent verified SQL pools and JWT authorities redeem exactly once',
  { timeout: 30000 },
  async () => {
    const fixture = await apiKeyFixture(),
      key = randomBytes(32);
    let app: Awaited<ReturnType<typeof createApplication>> | undefined;
    const children: ReturnType<typeof fork>[] = [];
    try {
      const account = await fixture.session({ scope: 'magiclink:manage' });
      app = await createApplication({
        service: { name: 'magiclink-process-issuer', version: '1.0.0', environment: 'test' },
        logging: { level: 'silent' },
        plugins: [
          loggingPlugin(),
          magicLinksPlugin({
            stateStore: {
              store: fixture.backend.store,
              securityLevel: 'test-only',
              operationTimeoutMs: 5000,
            },
            hmac: nativeFixtureHmac(key),
            signingKeyRef: 'fixture/magiclink',
            trustedBaseUrl: 'https://identity.fixture.invalid/confirm',
            ttlMs: 60000,
            maxClaimsPerHour: 8,
            authority: {
              async require(_action, hint) {
                const current = fixture.currentIdentity();
                if (current !== account.identity || (hint && hint !== account.subject))
                  throw new Error('A verified current session is required');
                return account.subject;
              },
            },
          }),
        ],
      });
      await app.start();
      const magic = app.resolve<MagicLinkService>(MAGICLINK_CAPABILITY);
      const issued = await account.run(() => magic.issue(account.subject, 'login'));
      const workers = Array.from({ length: 2 }, () => {
        const child = fork(new URL('./magiclink-worker.js', import.meta.url), [], {
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
          serialization: 'advanced',
        });
        children.push(child);
        const ready = new Promise<void>((resolve, reject) => {
          child.on('message', (message) => {
            if ((message as { type: string }).type === 'ready') resolve();
            if ((message as { type: string }).type === 'failed')
              reject(new Error('The independent magic-link worker failed startup'));
          });
          child.once('error', reject);
          child.once('exit', (code) => {
            if (code !== 0) reject(new Error('The independent magic-link worker exited'));
          });
        });
        const result = new Promise<string>((resolve, reject) => {
          child.on('message', (message) => {
            const value = message as { type: string; result: string };
            if (value.type === 'result') resolve(value.result);
            if (value.type === 'failed')
              reject(new Error('The independent magic-link worker failed'));
          });
          child.once('error', reject);
          child.once('exit', (code) => {
            if (code !== 0) reject(new Error('The independent magic-link worker exited'));
          });
        });
        void result.catch(() => undefined);
        const exit = once(child, 'exit');
        // Credentials travel only through the owned IPC channel, never process arguments or output.
        child.send({
          type: 'start',
          schema: fixture.backend.schema,
          issuer: fixture.issuer.authority,
          bearer: account.token,
          key,
        });
        return { child, ready, result, exit };
      });
      await Promise.all(workers.map((worker) => worker.ready));
      for (const worker of workers) worker.child.send({ type: 'consume', token: issued.value });
      assert.deepEqual((await Promise.all(workers.map((worker) => worker.result))).sort(), [
        'EK_MAGICLINK_REPLAY',
        'accepted',
      ]);
      for (const [code] of await Promise.all(workers.map((worker) => worker.exit)))
        assert.equal(code, 0);
    } finally {
      await Promise.all(
        children
          .filter((child) => child.exitCode === null)
          .map(async (child) => {
            const exit = once(child, 'exit');
            child.kill('SIGTERM');
            await exit;
          }),
      );
      try {
        await app?.stop();
      } finally {
        key.fill(0);
        await fixture.close();
      }
    }
  },
);
