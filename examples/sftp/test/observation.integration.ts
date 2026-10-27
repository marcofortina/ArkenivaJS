// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { sftpPlugin, SSH_CAPABILITY } from '@arkenivajs/sftp';
import type { SshService } from '@arkenivajs/sftp';
import { fixtureSettings } from '../dist/main.js';

test('The native SSH SDK exports actual bounded output sizes without credentials, paths or command data', async () => {
  const envelopes: {
      resourceMetrics?: {
        scopeMetrics: {
          metrics: { name: string; unit: string; histogram?: { dataPoints: { sum: number }[] } }[];
        }[];
      }[];
    }[] = [],
    logs: string[] = [],
    fixture = await fixtureSettings();
  const collector = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    envelopes.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    response.setHeader('content-type', 'application/json');
    response.end('{}');
  });
  await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
  const endpoint = collector.address();
  assert.ok(endpoint && typeof endpoint === 'object');
  const destination = new Writable({
      write(chunk: Buffer, _encoding, done) {
        logs.push(chunk.toString('utf8'));
        done();
      },
    }),
    app = await createApplication({
      service: { name: 'sftp-observation', version: '0.1.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      plugins: [
        sftpPlugin(fixture.settings),
        loggingPlugin({ destination }),
        telemetryPlugin({
          endpoint: 'http://127.0.0.1:' + endpoint.port,
          allowInsecureLoopback: true,
          exportTimeoutMs: 1000,
          exportIntervalMs: 1000,
        }),
      ],
    });
  try {
    await app.start();
    const ssh = app.resolve<SshService>(SSH_CAPABILITY),
      value = 'private-command-argument';
    const result = await ssh.exec('fixture', 'report', { value });
    assert.equal(result.stdout.length, Buffer.byteLength(value));
    await assert.rejects(ssh.exec('fixture', 'forbidden-private-command', {}));
    await app.telemetry.flush();
    await app.logger.flush();
    const metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics)),
      output = metrics.find((metric) => metric.name === 'sftp.command.output.bytes');
    assert.equal(output?.unit, 'By');
    assert.equal(output?.histogram?.dataPoints[0]?.sum, Buffer.byteLength(value));
    assert.ok(
      metrics.some(
        (metric) => metric.name === 'sftp.operation.duration.ms' && metric.unit === 'ms',
      ),
    );
    assert.ok(logs.some((line) => line.includes('SSH operation completed')));
    const wire = JSON.stringify(envelopes) + logs.join('');
    for (const privateValue of [
      value,
      'forbidden-private-command',
      fixture.directory,
      'fixture-key',
      'fixture-version',
    ])
      assert.equal(wire.includes(privateValue), false);
    assert.equal(wire.includes('PRIVATE KEY'), false);
  } finally {
    try {
      await app.stop();
    } finally {
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
      destination.end();
      fixture.clear();
    }
  }
});
