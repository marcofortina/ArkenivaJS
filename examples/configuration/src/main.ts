// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import { createConfig, configPlugin } from '@arkenivajs/config';

/** Load a strict configuration, use an isolated application, then close its resources. */
export async function runConfigurationExample(
  environment: Readonly<Record<string, string | undefined>> = {},
): Promise<{ greeting: string }> {
  const config = await createConfig<{ greeting: string }>({
    workspace: process.cwd(),
    schema: {
      type: 'object',
      properties: { greeting: { type: 'string', minLength: 1 } },
      required: ['greeting'],
      additionalProperties: false,
    },
    defaults: { greeting: 'Hello from defaults' },
    yamlText: 'greeting: Hello from YAML',
    environment,
    environmentFields: { ARKENIVAJS_GREETING: { path: 'greeting', type: 'string' } },
    dynamicPaths: ['greeting'],
  });
  const app = await createApplication({
    service: { name: 'configuration-example', version: '1.0.0', environment: 'development' },
    plugins: [configPlugin(config)],
  });
  try {
    await app.start();
    return { greeting: config.require('greeting') };
  } finally {
    await app.stop();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runConfigurationExample(process.env)));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The example could not finish' },
      ),
    );
    process.exitCode = 1;
  }
}
