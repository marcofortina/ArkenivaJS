// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import { nativeDns, dnsSettings, dnsWorkload, verifyDns } from './dns-workload.mjs';
const originalResolvers = dns.getServers();
process.once('beforeExit', () => assert.deepEqual(dns.getServers(), originalResolvers));
runPureWorker({
  name: 'dns',
  retainRawSamples: true,
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  native: nativeDns,
  async framework(fixture) {
    const { dnsPlugin, DNS_CAPABILITY } = await import('@arkenivajs/dns');
    return { plugin: dnsPlugin(dnsSettings(fixture)), key: DNS_CAPABILITY };
  },
  async verify(service, fixture) {
    const result = await verifyDns(service, fixture);
    assert.deepEqual(dns.getServers(), originalResolvers);
    return { ...result, globalResolversUnchanged: true };
  },
  workload: dnsWorkload,
  close: (service) => service?.close(),
});
