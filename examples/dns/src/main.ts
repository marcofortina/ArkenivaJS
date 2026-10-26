// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createDnsService } from '@arkenivajs/dns';
import { startDnsFixture } from './fixture.js';

/** Exercise a real native resolver against an owned loopback server with deterministic data. */
export async function runDnsExample() {
  const fixture = await startDnsFixture(),
    dns = createDnsService({
      resolvers: [{ name: 'lab', servers: [fixture.server] }],
      maxConcurrency: 4,
      timeoutMs: 1000,
    });
  try {
    const a = await dns.resolve({ hostname: 'internal.test', type: 'A' }),
      srv = await dns.resolve({ hostname: '_postgresql._tcp.internal.test', type: 'SRV' }),
      txt = await dns.resolve({ hostname: 'internal.test', type: 'TXT' }),
      os = await dns.lookup('127.0.0.1', { family: 4, all: true });
    return Object.freeze({
      aRecords: a.length,
      srvRecords: srv.length,
      txtRecords: txt.length,
      firstTxtSegments: txt[0]!.segments.length,
      ttlObserved: a[0]!.ttlSeconds === 30,
      osLookupDistinct: os[0]!.address === '127.0.0.1',
    });
  } finally {
    await dns.close();
    await fixture.close();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(await runDnsExample()));
