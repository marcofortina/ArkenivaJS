// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import dns from 'node:dns/promises';

export const dnsTypes = Object.freeze([
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'PTR',
  'SOA',
  'SRV',
  'TXT',
  'CAA',
  'NAPTR',
]);
export const dnsSettings = (fixture) => ({
  resolvers: [{ name: 'lab', servers: [fixture.server] }],
  defaultResolver: 'lab',
  maxConcurrency: 1,
  timeoutMs: 1000,
});

/** Native c-ares/getaddrinfo calls and result shaping on the controlled authority, without framework instrumentation. */
export function nativeDns(fixture) {
  const withoutType = (row) => {
    const { type, ...value } = row;
    void type;
    return value;
  };
  const resolver = new dns.Resolver({ timeout: 1000, tries: 1 });
  resolver.setServers([fixture.server]);
  return {
    async resolve({ hostname, type }) {
      if (type === 'A' || type === 'AAAA') {
        const answers = await (type === 'A'
          ? resolver.resolve4(hostname, { ttl: true })
          : resolver.resolve6(hostname, { ttl: true }));
        return answers.map((row) => ({ address: row.address, ttlSeconds: row.ttl }));
      }
      if (['CNAME', 'NS', 'PTR'].includes(type)) {
        const method = { CNAME: 'resolveCname', NS: 'resolveNs', PTR: 'resolvePtr' }[type];
        return (await resolver[method](hostname)).map((value) => ({ hostname: value }));
      }
      if (type === 'TXT')
        return (await resolver.resolveTxt(hostname)).map((segments) => ({ segments }));
      if (type === 'SOA') return [withoutType(await resolver.resolveSoa(hostname))];
      if (type === 'CAA')
        return (await resolver.resolveCaa(hostname)).map((row) => {
          const tag = Object.keys(row).find((key) => key !== 'critical' && key !== 'type');
          return { critical: row.critical, tag, value: row[tag] };
        });
      const method = { MX: 'resolveMx', SRV: 'resolveSrv', NAPTR: 'resolveNaptr' }[type];
      return (await resolver[method](hostname)).map(withoutType);
    },
    async lookup(hostname, options) {
      const value = await dns.lookup(hostname, options);
      return Array.isArray(value) ? value : [value];
    },
    reverse: (address) => resolver.reverse(address),
    getResolvers: () => Object.freeze(['lab']),
    close() {
      resolver.cancel();
    },
  };
}

export function dnsWorkload(service, fixture) {
  let sequence = 0;
  const work = Object.fromEntries(
    dnsTypes.map((type) => [
      'resolve' + type,
      () => service.resolve({ hostname: 'sample' + sequence++ + '.' + fixture.hostname, type }),
    ]),
  );
  return Object.freeze({
    ...work,
    lookupOs: () => service.lookup('127.0.0.1', { family: 4, all: true }),
    reverse: () => service.reverse('198.51.100.' + (1 + (sequence++ % 200))),
    resolverNames: () => service.getResolvers(),
  });
}

export async function verifyDns(service, fixture) {
  const expected = {
    A: [{ address: '192.0.2.11', ttlSeconds: 30 }],
    AAAA: [{ address: '2001:db8::1', ttlSeconds: 30 }],
    CNAME: [{ hostname: 'target.internal.test' }],
    NS: [{ hostname: 'ns.internal.test' }],
    PTR: [{ hostname: 'ptr.internal.test' }],
    MX: [{ exchange: 'mail.internal.test', priority: 10 }],
    SRV: [{ name: 'db.internal.test', port: 5432, priority: 10, weight: 5 }],
    TXT: [{ segments: ['first', 'second'] }, { segments: ['separate'] }],
    SOA: [
      {
        nsname: 'ns.internal.test',
        hostmaster: 'hostmaster.internal.test',
        serial: 42,
        refresh: 300,
        retry: 60,
        expire: 3600,
        minttl: 30,
      },
    ],
    CAA: [{ critical: 0, tag: 'issue', value: 'ca.internal.test' }],
    NAPTR: [
      {
        order: 10,
        preference: 20,
        flags: 'S',
        service: 'SIP+D2U',
        regexp: '',
        replacement: '_sip._udp.internal.test',
      },
    ],
  };
  for (const type of dnsTypes)
    assert.deepEqual(await service.resolve({ hostname: fixture.hostname, type }), expected[type]);
  assert.deepEqual(await service.lookup('127.0.0.1', { family: 4, all: true }), [
    { address: '127.0.0.1', family: 4 },
  ]);
  assert.deepEqual(await service.reverse('192.0.2.25'), ['ptr.internal.test']);
  assert.deepEqual(service.getResolvers(), ['lab']);
  return { checkedRecordFamilies: dnsTypes.length, osLookupAndReverse: true, resolverNames: true };
}
