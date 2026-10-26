// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError, COMPONENTS } from '@arkenivajs/core';
import type { ConfigService, Plugin } from '@arkenivajs/core';
import { createConfig, configPlugin } from '@arkenivajs/config';

/** One application-owned service key; matching descriptions never replace symbol identity. */
export const COUNTER_CAPABILITY = Symbol('configuration-example.counter');
/** A retained handle owns an explicit closed state independently of application lookup. */
export interface CounterService {
  /** Reject calls once the plugin releases its resources. */
  next(): number;
}

/** Compose a configured service and exercise scoped initialization, runtime lookup and shutdown. */
export async function runCapabilitiesExample(): Promise<{
  initializationValue: number;
  readyValue: number;
  missingOptional: boolean;
  closedCode: string;
  releasedHandleCode: string;
}> {
  const config = await createConfig<{ step: number }>({
    workspace: process.cwd(),
    defaults: { step: 2 },
    schema: {
      type: 'object',
      properties: { step: { type: 'integer', minimum: 1, maximum: 100 } },
      required: ['step'],
      additionalProperties: false,
    },
  });
  let initializationValue = 0,
    closeCounter!: () => void;
  const provider: Plugin = {
    id: 'counter',
    version: '1.0.0',
    capabilities: new Set(['counter']),
    dependencies: ['config'],
    init(context) {
      const step = context
        .require<ConfigService<{ step: number }>>(COMPONENTS.config)
        .require('step');
      let value = 0,
        closed = false;
      const counter: CounterService = Object.freeze({
        next() {
          if (closed)
            throw new KitError({
              code: 'EK_RESOURCE_CLOSED',
              message: 'The example counter is closed',
            });
          value += step;
          return value;
        },
      });
      closeCounter = () => {
        closed = true;
      };
      context.provide(COUNTER_CAPABILITY, counter);
    },
    close() {
      closeCounter();
    },
  };
  const consumer: Plugin = {
    id: 'consumer',
    version: '1.0.0',
    capabilities: new Set(),
    dependencies: ['counter'],
    async init() {
      await Promise.resolve();
      initializationValue = app.resolve<CounterService>(COUNTER_CAPABILITY).next();
    },
    close() {},
  };
  const app = await createApplication({
    service: { name: 'capabilities-example', version: '1.0.0', environment: 'test' },
    plugins: [consumer, provider, configPlugin(config)],
  });
  let counter!: CounterService, readyValue: number, missingOptional: boolean;
  try {
    await app.start();
    counter = app.resolve<CounterService>(COUNTER_CAPABILITY);
    readyValue = counter.next();
    missingOptional = app.tryResolve(Symbol('configuration-example.counter')) === undefined;
  } finally {
    await app.stop();
  }
  const rejected = (work: () => unknown): string => {
    try {
      work();
    } catch (error) {
      if (error instanceof KitError) return error.code;
      throw error;
    }
    throw new Error('Expected the released capability to reject');
  };
  return {
    initializationValue,
    readyValue,
    missingOptional,
    closedCode: rejected(() => app.resolve(COUNTER_CAPABILITY)),
    releasedHandleCode: rejected(() => counter.next()),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runCapabilitiesExample()));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The capability example could not finish' },
      ),
    );
    process.exitCode = 1;
  }
}
