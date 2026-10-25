import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Writable } from 'node:stream';
import { createApplication, KitError } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { apiPlugin } from '@arkenivajs/api';
import { healthPlugin } from '@arkenivajs/health';
import { redisPlugin } from '@arkenivajs/database-redis';

/** Start with local lifecycle readiness; optionally probe an explicitly authorized disposable Redis. */
export async function createHealthApplication(
  options: { port?: number; redis?: boolean; destination?: Writable } = {},
) {
  const port = options.port ?? 8080;
  if (
    !Number.isSafeInteger(port) ||
    port < 1 ||
    port > 65535 ||
    (options.redis !== undefined && typeof options.redis !== 'boolean')
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The health example requires a valid port and explicit Redis policy',
    });
  if (
    options.redis &&
    (process.env.ARKENIVA_REDIS_DISPOSABLE !== '1' || !process.env.ARKENIVA_REDIS_URL)
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The Redis example requires an explicitly disposable authenticated fixture',
    });
  return createApplication({
    service: { name: 'health-example', version: '1.0.0', environment: 'development' },
    http: { host: '127.0.0.1', port },
    ...(options.redis
      ? {
          databases: {
            values: { driver: 'redis' as const, connectionStringEnv: 'ARKENIVA_REDIS_URL' },
          },
        }
      : {}),
    plugins: [
      loggingPlugin(options.destination ? { destination: options.destination } : {}),
      apiPlugin(),
      healthPlugin(),
      ...(options.redis ? [redisPlugin()] : []),
    ],
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (
      process.argv.slice(2).some((argument) => argument !== '--redis') ||
      process.argv.slice(2).length > 1
    )
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Only the explicit --redis option is supported',
      });
    const port =
      process.env.ARKENIVAJS_PORT === undefined ? 8080 : Number(process.env.ARKENIVAJS_PORT);
    const app = await createHealthApplication({ port, redis: process.argv.includes('--redis') });
    await app.start();
    app.logger.info('Health example ready', { port });
    let stopping = false;
    const stop = async () => {
      if (stopping) return;
      stopping = true;
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);
      try {
        await app.stop();
      } catch (cause) {
        console.error(
          JSON.stringify(
            cause instanceof KitError
              ? cause.toSafeJSON()
              : { code: 'EK_INTERNAL', message: 'The health example could not stop' },
          ),
        );
        process.exitCode = 1;
      }
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  } catch (cause) {
    console.error(
      JSON.stringify(
        cause instanceof KitError
          ? cause.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The health example could not start' },
      ),
    );
    process.exitCode = 1;
  }
}
