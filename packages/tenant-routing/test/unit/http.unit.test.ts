// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpUpstreams } from '../../dist/http.js';
import { captureSettings } from '../../dist/settings.js';
import { settings } from '../http-fixture.js';

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
