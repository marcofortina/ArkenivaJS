// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ApplicationOptions, PluginContext } from '@arkenivajs/core';
import { PREPARE_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import { realtimePlugin } from '../../dist/index.js';

test('Production and development reject explicitly test-only realtime providers before acquiring transport capabilities', async () => {
  for (const environment of ['production', 'development'] as const)
    for (const component of ['source', 'authority'] as const) {
      const settings = {
        routes: [],
        websocketHandlers: {},
        sseSources:
          component === 'source'
            ? {
                events: {
                  kind: 'pubsub' as const,
                  usage: 'test-only' as const,
                  async *subscribe() {
                    yield { id: 'test', type: 'test', data: 'test' };
                  },
                },
              }
            : {},
        policies: {},
        policy: { maxConcurrent: 1, timeoutMs: 1000 },
        ...(component === 'authority'
          ? {
              identityAuthority: {
                usage: 'test-only' as const,
                async authenticate(): Promise<never> {
                  throw new Error('Test authority must never run');
                },
              },
            }
          : {}),
      };
      const plugin = realtimePlugin(settings) as ComposablePlugin;
      const options: ApplicationOptions = {
        service: { name: 'environment-check', version: '1.0.0', environment },
      };
      plugin[PREPARE_PLUGIN]!({ options, state: () => 'INITIALIZING' });
      let acquired = 0;
      const context = {
        options,
        require() {
          acquired++;
          throw new Error('Transport acquisition must not run');
        },
      } as unknown as PluginContext;
      await assert.rejects(async () => plugin.init(context), { code: 'EK_CONFIG_INVALID' });
      assert.equal(acquired, 0);
    }
});
