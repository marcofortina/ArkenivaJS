import { createMeter } from '@arkenivajs/metering';
import type { MeteringEvent, TenantId, VerifiedTenantContext } from '@arkenivajs/core';
export async function records(count = 1) {
  const tenant: VerifiedTenantContext = Object.freeze({
    tenantId: 'tenant-export' as TenantId,
    identity: {
      subject: 'example',
      issuer: 'https://issuer.invalid',
      audience: ['api'],
      scopes: [],
      claims: {},
    },
    verifiedAt: new Date().toISOString(),
    source: 'oidc',
  });
  const events: MeteringEvent[] = [];
  const meter = createMeter({
    service: { name: 'export-test', version: '1.0.0', environment: 'test' },
    auth: { isVerifiedTenant: (value): value is VerifiedTenantContext => value === tenant },
    exporter: {
      kind: 'jsonl',
      async export(batch) {
        events.push(...batch);
      },
      async close() {},
    },
  });
  try {
    for (let index = 0; index < count; index++)
      meter.start({ tenant, operation: 'test.' + 'a'.repeat(200) }).end('ok');
    await meter.flush();
    return events;
  } finally {
    await meter.close();
  }
}
