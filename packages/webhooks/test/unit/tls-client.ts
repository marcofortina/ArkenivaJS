// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { fixture, fixtureSettings } from './fixture.js';

if (
  process.env.ARKENIVA_WEBHOOKS_DISPOSABLE !== '1' ||
  !/^https:\/\/127\.0\.0\.1:\d+$/.test(process.argv[2] ?? '')
)
  throw new Error('The TLS client requires the owned disposable webhook fixture');
const f = await fixture(fixtureSettings(process.argv[2]));
try {
  const receipt = await f.asTenant('tenant-a', () =>
    f.service.send('receiver', { id: 'one', type: 'fixture', payload: null }),
  );
  console.log(JSON.stringify({ status: receipt.status, attemptCount: receipt.attemptCount }));
} finally {
  await f.close();
}
