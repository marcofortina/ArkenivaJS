// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import type { Writable } from 'node:stream';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application } from '@arkenivajs/core';
import { createConfig } from '@arkenivajs/config';
import { apiPlugin } from '@arkenivajs/api';
import { httpPlugin } from '@arkenivajs/http';
import { loggingPlugin } from '@arkenivajs/logging';
import { diagnosticsPlugin } from '@arkenivajs/diagnostics';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import type { ManagedTelemetry } from '@arkenivajs/telemetry';

async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (!address || typeof address !== 'object') throw new Error('Example port is unavailable');
  return address.port;
}
/** Execute two isolated applications over real HTTP and export their measured trace/metric data. */
export async function runDistributedExample(
  endpoint: string,
  destination?: Writable,
): Promise<Readonly<{ value: string; traceId: string; downstreamTraceId: string }>> {
  const apps: Application[] = [];
  let failure: unknown;
  let failed = false;
  const errors: unknown[] = [];
  let output: Readonly<{ value: string; traceId: string; downstreamTraceId: string }> | undefined;
  try {
    const childPort = await availablePort();
    const common = (route: string) => [
      loggingPlugin(destination ? { destination } : {}),
      diagnosticsPlugin({ eventLoopUtilization: true }),
      telemetryPlugin({ endpoint, allowInsecureLoopback: true, labelValues: { route: [route] } }),
      apiPlugin({ dependencies: ['telemetry'] }),
    ];
    const child = await createApplication({
      service: { name: 'trace-example-child', version: '1.0.0', environment: 'test' },
      telemetry: { mode: 'detailed' },
      http: { host: '127.0.0.1', port: childPort },
      plugins: common('/step'),
    });
    apps.push(child);
    const payload = {
      type: 'object',
      properties: {
        value: { type: 'string' },
        downstreamTraceId: { type: 'string', pattern: '^[0-9a-f]{32}$' },
      },
      required: ['value', 'downstreamTraceId'],
      additionalProperties: false,
    };
    child.api.get('/step', {
      schema: { response: payload },
      auth: { required: false },
      handler: (context) => {
        if (context.auth) throw new Error('Public routes must not gain tenant authorization');
        child.logger.info('Downstream work completed');
        return {
          value: 'ok',
          downstreamTraceId: (child.telemetry as ManagedTelemetry).currentTraceId()!,
        };
      },
    });
    const parentPort = await availablePort(),
      origin = `http://127.0.0.1:${childPort}`;
    const parent = await createApplication({
      service: { name: 'trace-example-parent', version: '1.0.0', environment: 'test' },
      telemetry: { mode: 'detailed' },
      http: { host: '127.0.0.1', port: parentPort },
      plugins: [
        ...common('/chain'),
        httpPlugin({
          allowedOrigins: [origin],
          allowPrivateNetwork: true,
          dependencies: ['telemetry'],
        }),
      ],
    });
    apps.push(parent);
    parent.api.get('/chain', {
      schema: { response: payload },
      auth: { required: false },
      handler: async (context) => {
        parent.logger.info('Outbound work started');
        return (await parent.http.get(origin + '/step', { signal: context.signal })).json();
      },
    });
    await child.start();
    await parent.start();
    const before = parent.diagnostics.snapshot(),
      traceId = randomBytes(16).toString('hex');
    const reply = await fetch(`http://127.0.0.1:${parentPort}/chain`, {
      signal: AbortSignal.timeout(5000),
      headers: {
        traceparent: `00-${traceId}-${randomBytes(8).toString('hex')}-01`,
        baggage: 'tenant_id=untrusted-example',
      },
    });
    if (reply.status !== 200) throw new Error('Example request failed');
    const body = (await reply.json()) as { value: string; downstreamTraceId: string };
    if (body.value !== 'ok' || body.downstreamTraceId !== traceId)
      throw new Error('Distributed trace correlation failed');
    const after = parent.diagnostics.snapshot();
    parent.telemetry.addCounter(
      'arkenivajs.process.cpu.time',
      (after.cpuUserMicros - before.cpuUserMicros) / 1_000_000,
      { state: 'user' },
    );
    parent.telemetry.addCounter(
      'arkenivajs.process.cpu.time',
      (after.cpuSystemMicros - before.cpuSystemMicros) / 1_000_000,
      { state: 'system' },
    );
    parent.telemetry.setGauge('arkenivajs.process.memory.rss', after.memoryRssBytes, {
      service: 'trace-example-parent',
    });
    if (after.eventLoopUtilization !== undefined)
      parent.telemetry.setGauge(
        'arkenivajs.runtime.event_loop.utilization',
        after.eventLoopUtilization,
        { service: 'trace-example-parent' },
      );
    await parent.telemetry.flush();
    await child.telemetry.flush();
    output = Object.freeze({
      value: body.value,
      traceId,
      downstreamTraceId: body.downstreamTraceId,
    });
  } catch (error) {
    failure = error;
    failed = true;
  } finally {
    for (const app of apps.reverse()) {
      try {
        await app.stop();
      } catch (error) {
        errors.push(error);
      }
    }
  }
  if (errors.length)
    throw new AggregateError(
      failed ? [failure, ...errors] : errors,
      'Example resource cleanup failed',
      { cause: failure },
    );
  if (failed) throw failure;
  return output!;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const config = await createConfig<{ endpoint: string }>({
      workspace: process.cwd(),
      schema: {
        type: 'object',
        properties: { endpoint: { type: 'string', minLength: 1 } },
        required: ['endpoint'],
        additionalProperties: false,
      },
      defaults: { endpoint: 'http://127.0.0.1:4318' },
      environment: process.env,
      environmentFields: { ARKENIVAJS_OTLP_ENDPOINT: { path: 'endpoint', type: 'string' } },
    });
    console.log(JSON.stringify(await runDistributedExample(config.require('endpoint'))));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'Distributed example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
