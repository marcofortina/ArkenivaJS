// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpUpstreams } from '../../dist/http.js';
import { captureSettings } from '../../dist/settings.js';
import { settings } from '../http-fixture.js';
import type { ApprovedUpstream, TenantRoutingPluginSettings } from '../../dist/index.js';

test('Malformed destination and service scope catalogs fail before any credential request', async () => {
  const approved: ApprovedUpstream = {
    key: 'partner',
    origin: 'https://partner.example',
    allowedHostnames: ['partner.example'],
    allowedCidrs: ['10.0.0.0/8'],
    connectionTimeoutMs: 1000,
    allowRedirects: false,
  };
  let credentials = 0;
  const configuration = (approvedUpstreams: readonly ApprovedUpstream[]) =>
    captureSettings({
      ...settings(),
      approvedUpstreams,
      credentialProvider: {
        async get() {
          credentials++;
          throw new Error('Invalid destination policy must not request credentials');
        },
      },
    });
  const invalid: readonly Record<string, unknown>[] = [
    { allowedHostnames: [] },
    { allowedHostnames: 'partner.example' },
    { allowedHostnames: ['partner.example', 'partner.example'] },
    { allowedHostnames: Array.from({ length: 65 }, (_, index) => `host${index}.example`) },
    { allowedCidrs: [] },
    { allowedCidrs: ['10.0.0.0/8', '10.0.0.0/8'] },
    { serviceAuth: { audience: 'api://partner', scopes: ['orders:read orders:write'] } },
    { serviceAuth: { audience: 'api://partner', scopes: ['x'.repeat(129)] } },
    { serviceAuth: { audience: 'api://partner', scopes: ['orders:read', 'orders:read'] } },
    { origin: 'http://partner.example', tlsCaFile: '/trusted/ca.pem' },
  ];
  for (const patch of invalid) {
    const captured = configuration([{ ...approved, ...patch } as ApprovedUpstream]);
    await assert.rejects(HttpUpstreams.create(captured, 'test', new AbortController().signal), {
      code: 'EK_TROUTE_REGISTRY',
      message: 'Invalid tenant routing registry',
    });
  }
  await assert.rejects(
    HttpUpstreams.create(configuration([approved, approved]), 'test', new AbortController().signal),
    { code: 'EK_TROUTE_REGISTRY' },
  );
  assert.equal(credentials, 0);
  const valid: TenantRoutingPluginSettings = {
    ...settings(),
    approvedUpstreams: [{ ...approved, serviceAuth: { audience: 'api://partner', scopes: [] } }],
    credentialProvider: {
      async get() {
        credentials++;
        throw new Error('Creating a pool must not request credentials');
      },
    },
  };
  const recovered = await HttpUpstreams.create(
    captureSettings(valid),
    'production',
    new AbortController().signal,
  );
  await recovered.close();
  assert.equal(credentials, 0);
});

test('Production transport rejects cleartext, loopback and metadata even when startup catalogs allow them', async () => {
  for (const [origin, host, cidr] of [
    ['http://partner.example', 'partner.example', '10.0.0.0/8'],
    ['https://127.0.0.1', '127.0.0.1', '127.0.0.0/8'],
    ['https://169.254.169.254', '169.254.169.254', '169.254.0.0/16'],
    ['https://100.100.100.200', '100.100.100.200', '100.64.0.0/10'],
    ['https://[::1]', '::1', '::1/128'],
    ['https://[fd00:ec2::254]', 'fd00:ec2::254', 'fd00::/8'],
  ]) {
    const captured = captureSettings({
      ...settings(),
      approvedUpstreams: [
        {
          key: 'partner',
          origin: origin!,
          allowedHostnames: [host!],
          allowedCidrs: [cidr!],
          connectionTimeoutMs: 1000,
          allowRedirects: false,
        },
      ],
    });
    await assert.rejects(
      HttpUpstreams.create(captured, 'production', new AbortController().signal),
      {
        code: 'EK_TROUTE_REGISTRY',
      },
    );
  }
});

test('Startup cancellation rejects without publishing pools while explicitly approved private HTTPS remains available', async () => {
  const captured = captureSettings({
    ...settings(),
    approvedUpstreams: [
      {
        key: 'partner',
        origin: 'https://partner.example',
        allowedHostnames: ['partner.example'],
        allowedCidrs: ['10.0.0.0/8'],
        connectionTimeoutMs: 1000,
        allowRedirects: false,
      },
    ],
  });
  await assert.rejects(HttpUpstreams.create(captured, 'production', AbortSignal.abort()), {
    code: 'EK_TROUTE_REGISTRY',
  });
  const pools = await HttpUpstreams.create(captured, 'production', new AbortController().signal);
  await pools.close();
  await pools.close();
});
