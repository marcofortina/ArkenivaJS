import { KitError, METER_EVENT_SCHEMA_VERSION } from '@arkenivajs/core';
import type { Environment, OperationOptions, MeteringEvent } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { createHttpClient } from '@arkenivajs/http';
import type { MeterExporter } from './index.js';
import { parseMeteringEvent } from './event.js';

/** Endpoint and credential policy are trusted deployment configuration, never request-derived. */
export interface HttpMeterExporterOptions {
  readonly endpoint: string;
  readonly authorization: () => Promise<string> | string;
  readonly environment?: Environment;
  readonly allowInsecureLoopback?: boolean;
  readonly allowPrivateNetwork?: boolean;
}
/** Dedicated authenticated TLS event transport; only 202 acknowledges the entire versioned batch. */
export function createHttpMeterExporter(options: HttpMeterExporterOptions): MeterExporter {
  let endpoint: URL;
  try {
    endpoint = new URL(options.endpoint);
    const insecure =
      options.allowInsecureLoopback === true &&
      options.environment !== 'production' &&
      options.environment !== undefined &&
      endpoint.protocol === 'http:' &&
      ['127.0.0.1', '[::1]'].includes(endpoint.hostname);
    if (
      endpoint.username ||
      endpoint.password ||
      endpoint.hash ||
      endpoint.search ||
      endpoint.pathname !== '/' ||
      (endpoint.protocol !== 'https:' && !insecure) ||
      typeof options.authorization !== 'function' ||
      (options.allowInsecureLoopback !== undefined &&
        typeof options.allowInsecureLoopback !== 'boolean') ||
      (options.allowPrivateNetwork !== undefined &&
        typeof options.allowPrivateNetwork !== 'boolean') ||
      (options.allowInsecureLoopback &&
        !['test', 'development'].includes(options.environment ?? 'production')) ||
      (options.environment !== undefined &&
        !['test', 'development', 'production'].includes(options.environment))
    )
      throw new Error('Invalid collector trust policy');
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid authenticated metering collector policy',
      cause,
    });
  }
  const authorization = options.authorization;
  const client = createHttpClient({
    allowedOrigins: [endpoint.origin],
    allowPrivateNetwork:
      options.allowInsecureLoopback === true || options.allowPrivateNetwork === true,
    timeoutMs: 5000,
    maxResponseBytes: 65_536,
    connections: 1,
  });
  let closed = false;
  const controller = new AbortController();
  return Object.freeze({
    kind: 'http' as const,
    async export(events: readonly MeteringEvent[], operation: OperationOptions = {}) {
      if (closed)
        throw new KitError({
          code: 'EK_RESOURCE_CLOSED',
          message: 'Meter HTTP exporter is closed',
        });
      if (!Array.isArray(events) || events.length < 1 || events.length > 1000)
        throw new KitError({ code: 'EK_METER_EXPORT', message: 'Invalid meter HTTP batch size' });
      const batch = events.map(parseMeteringEvent);
      const attemptController = new AbortController();
      const signal = AbortSignal.any([
        controller.signal,
        attemptController.signal,
        ...(operation.signal ? [operation.signal] : []),
      ]);
      const bounded = { signal, timeoutMs: operation.timeoutMs ?? 5000 };
      return within(async () => {
        const credential = await within(authorization, bounded);
        if (
          typeof credential !== 'string' ||
          credential.length > 16_384 ||
          !new RegExp('^Bearer [A-Za-z0-9._~+/-]+={0,2}(?![\\s\\S])').test(credential)
        )
          throw new KitError({
            code: 'EK_METER_EXPORT',
            message: 'Invalid collector authorization credential',
          });
        const response = await client.request(endpoint.origin + '/v1/metering/events', {
          method: 'POST',
          headers: {
            authorization: credential,
            'content-type': 'application/json',
            'x-arkenivajs-metering-version': METER_EVENT_SCHEMA_VERSION,
          },
          body: JSON.stringify({ schemaVersion: METER_EVENT_SCHEMA_VERSION, events: batch }),
          ...bounded,
        });
        if (response.status !== 202)
          throw new KitError({
            code: 'EK_METER_EXPORT',
            message: 'Collector did not acknowledge the complete event batch',
            retryable: response.status === 429 || response.status >= 500,
          });
      }, bounded)
        .catch((cause) => {
          if (cause instanceof KitError) {
            if (cause.code === 'EK_HTTP_UPSTREAM')
              throw new KitError({
                code: 'EK_METER_EXPORT',
                message: 'Metering collector transport failed',
                cause,
                retryable: cause.details.limitExceeded !== true,
              });
            throw cause;
          }
          throw new KitError({
            code: 'EK_METER_EXPORT',
            message: 'Metering collector operation failed',
            cause,
          });
        })
        .finally(() => attemptController.abort());
    },
    close(operation: OperationOptions = {}) {
      closed = true;
      controller.abort();
      return client.close(operation);
    },
  });
}
