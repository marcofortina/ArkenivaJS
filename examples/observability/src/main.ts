import { resolve } from 'node:path';
import type { Writable } from 'node:stream';
import { setTimeout } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import type { ProcessSnapshot } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { diagnosticsPlugin } from '@arkenivajs/diagnostics';

/** Emit safe service events and a real process snapshot, then close both plugins. */
export async function runObservabilityExample(
  destination: Writable = process.stdout,
): Promise<ProcessSnapshot> {
  const app = await createApplication({
    service: { name: 'observability-example', version: '1.0.0', environment: 'development' },
    logging: { level: 'info' },
    plugins: [
      loggingPlugin({ destination }),
      diagnosticsPlugin({ eventLoopDelay: true, resolutionMs: 10 }),
    ],
  });
  try {
    await app.start();
    const log = app.logger.child({ component: 'ExampleOperation', requestId: 'example-request' });
    log.warn('A recoverable operation failed', {
      credentials: { password: 'fake-example-password' },
      error: new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'Internal detail containing fake-example-secret',
        cause: new Error('Private native cause'),
        retryable: true,
      }),
    });
    await setTimeout(50);
    const snapshot = app.diagnostics.snapshot();
    log.info('Process snapshot captured', { snapshot });
    await app.logger.flush({ timeoutMs: 1000 });
    return snapshot;
  } finally {
    await app.stop({ timeoutMs: 1000 });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await runObservabilityExample();
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
