// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dnsPlugin } from '../../dist/index.js';
import type { DnsService } from '../../dist/index.js';

/** Compile native operation maps and negative public fixtures without network activity. */
export async function publicContract(dns: DnsService) {
  dnsPlugin({
    resolvers: [{ name: 'lab', servers: ['127.0.0.1:15353'] }],
    maxConcurrency: 1,
    timeoutMs: 1000,
  });
  const records = await dns.resolve({ hostname: 'internal.test', type: 'TXT' });
  const segments: readonly string[] | undefined = records[0]?.segments;
  // @ts-expect-error ANY and implicit encrypted DNS are outside this contract.
  await dns.resolve({ hostname: 'internal.test', type: 'ANY' });
  // @ts-expect-error OS lookup does not accept a named resolver server list.
  await dns.lookup('localhost', { resolver: 'lab' });
  // @ts-expect-error Runtime bounds are required.
  dnsPlugin({ resolvers: [] });
  return segments;
}
