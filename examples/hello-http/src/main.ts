import { resolve } from 'node:path';
import type { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import { createConfig } from '@arkenivajs/config';
import { apiPlugin } from '@arkenivajs/api';
import { httpPlugin } from '@arkenivajs/http';
import { loggingPlugin } from '@arkenivajs/logging';

/** Compose typed routes and an explicit loopback outbound policy before opening a listener. */
export async function createHelloApplication(
  input: {
    port?: number;
    environment?: Readonly<Record<string, string | undefined>>;
    destination?: Writable;
  } = {},
) {
  const config = await createConfig<{ port: number }>({
    workspace: process.cwd(),
    schema: {
      type: 'object',
      properties: { port: { type: 'integer', minimum: 1, maximum: 65535 } },
      required: ['port'],
      additionalProperties: false,
    },
    defaults: { port: 8080 },
    environment: input.environment ?? {},
    environmentFields: { ARKENIVAJS_PORT: { path: 'port', type: 'integer' } },
    ...(input.port === undefined ? {} : { runtime: { port: input.port } }),
  });
  const port = config.require('port');
  const origin = `http://127.0.0.1:${port}`;
  const app = await createApplication({
    service: { name: 'hello-http', version: '1.0.0', environment: 'development' },
    http: { host: '127.0.0.1', port },
    logging: { level: 'info' },
    plugins: [
      loggingPlugin(input.destination ? { destination: input.destination } : {}),
      apiPlugin(),
      httpPlugin({ allowedOrigins: [origin], allowPrivateNetwork: true }),
    ],
  });
  const params = {
    type: 'object',
    properties: { name: { type: 'string', minLength: 1, maxLength: 80 } },
    required: ['name'],
    additionalProperties: false,
  };
  const response = {
    type: 'object',
    properties: { greeting: { type: 'string' } },
    required: ['greeting'],
    additionalProperties: false,
  };
  app.api.get<{ name: string }, Record<string, never>, never, { greeting: string }>(
    '/hello/:name',
    {
      schema: { params, response },
      auth: { required: false },
      handler: ({ params }) => ({ greeting: `Hello ${params.name}` }),
    },
  );
  app.api.get<{ name: string }, Record<string, never>, never, { greeting: string }>(
    '/proxy/:name',
    {
      schema: { params, response },
      auth: { required: false },
      handler: async (ctx) => {
        const upstream = await app.http.get(
          origin + '/hello/' + encodeURIComponent(ctx.params.name),
          { signal: ctx.signal },
        );
        if (!upstream.ok)
          throw new KitError({
            code: 'EK_HTTP_UPSTREAM',
            message: 'The greeting service did not complete',
          });
        return (await upstream.json()) as { greeting: string };
      },
    },
  );
  return { app, origin };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { app, origin } = await createHelloApplication({ environment: process.env });
    await app.start();
    app.logger.info('HTTP example ready', { origin });
    let stopping = false;
    const stop = async () => {
      if (stopping) return;
      stopping = true;
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);
      try {
        await app.stop();
      } catch (error) {
        console.error(
          JSON.stringify(
            error instanceof KitError
              ? error.toSafeJSON()
              : { code: 'EK_INTERNAL', message: 'The example could not stop' },
          ),
        );
        process.exitCode = 1;
      }
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The example could not start' },
      ),
    );
    process.exitCode = 1;
  }
}
