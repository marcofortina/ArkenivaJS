// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { ldapPlugin, LDAP_CAPABILITY } from '@arkenivajs/security-ldap';
import type { LdapService, LdapSettings } from '@arkenivajs/security-ldap';

/** Owned test composition; real directory TLS remains mandatory, including on loopback. */
export async function runLdapExample(settings: LdapSettings, username: string, password: string) {
  if (settings.environment !== 'test')
    throw new Error('The disposable LDAP example requires a test environment');
  const logs: string[] = [],
    exports: string[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs.push(chunk.toString());
      done();
    },
  });
  const collector = createServer((request, response) => {
    void (async () => {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 4 * 1024 * 1024) throw new Error('Disposable metric export exceeds its limit');
        chunks.push(chunk);
      }
      exports.push(Buffer.concat(chunks).toString('utf8'));
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    })().catch(() => {
      response.statusCode = 400;
      response.end('{}');
    });
  });
  await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
  const address = collector.address();
  if (!address || typeof address === 'string')
    throw new Error('Disposable metric collector is unavailable');
  const app = await createApplication({
    service: { name: 'ldap-example', version: '0.1.0', environment: 'test' },
    logging: { level: 'debug' },
    telemetry: { mode: 'standard', samplingRatio: 1 },
    plugins: [
      loggingPlugin({ destination }),
      telemetryPlugin({
        endpoint: 'http://127.0.0.1:' + address.port,
        allowInsecureLoopback: true,
        exportIntervalMs: 1000,
        exportTimeoutMs: 1000,
      }),
      ldapPlugin(settings),
    ],
  });
  let result: { found: boolean; authenticated: boolean; groups: readonly string[] } | undefined;
  try {
    await app.start();
    const directory = app.resolve<LdapService>(LDAP_CAPABILITY),
      user = await directory.findUser({ username });
    const authenticated = await directory.verifyCredentials({ username }, password);
    const groups = user ? (await directory.getGroups(user.dn)).map((group) => group.name) : [];
    result = { found: user !== null, authenticated, groups };
  } finally {
    try {
      await app.stop();
    } finally {
      destination.destroy();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
    }
  }
  const diagnostics = [...logs, ...exports].join('\n');
  if (
    diagnostics.includes(password) ||
    diagnostics.includes(username) ||
    diagnostics.includes(settings.baseDn)
  )
    throw new Error('Directory diagnostics exposed fixture data');
  const metricNames = new Set<string>();
  for (const raw of exports) {
    const envelope = JSON.parse(raw) as {
      resourceMetrics?: { scopeMetrics?: { metrics?: { name: string }[] }[] }[];
    };
    for (const resource of envelope.resourceMetrics ?? [])
      for (const scope of resource.scopeMetrics ?? [])
        for (const metric of scope.metrics ?? []) metricNames.add(metric.name);
  }
  return {
    ...result,
    metricNames: [...metricNames].filter((name) => name.startsWith('ldap.')).sort(),
  };
}
