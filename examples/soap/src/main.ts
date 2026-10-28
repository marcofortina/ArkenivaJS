// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import type { Environment } from '@arkenivajs/core';
import { soapPlugin, SOAP_CAPABILITY } from '@arkenivajs/soap';
import type { SoapService, SoapPluginSettings } from '@arkenivajs/soap';
import { createFixture } from './fixture.js';

/** Reuse an application-owned service while closing each explicitly created native client lease. */
export async function readStock(soap: SoapService, sku: string) {
  const client = await soap.createClient('stock.v1');
  try {
    const result = await client.call<{ quantity: number }>(
      'ReadStock',
      { sku },
      { timeoutMs: 5000 },
    );
    if (!result.data || !Number.isSafeInteger(result.data.quantity))
      throw new Error('The inventory payload is invalid');
    return {
      quantity: result.data.quantity,
      status: result.status,
      correlationId: result.correlationId,
    };
  } finally {
    await client.close();
  }
}
export async function runSoapExample(
  settings: SoapPluginSettings,
  sku = '0007',
  environment: Environment = 'production',
) {
  const app = await createApplication({
    service: { name: 'soap-example', version: '0.1.0', environment },
    plugins: [soapPlugin(settings)],
  });
  try {
    await app.start();
    return await readStock(app.resolve<SoapService>(SOAP_CAPABILITY), sku);
  } finally {
    await app.stop();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let fixture: Awaited<ReturnType<typeof createFixture>> | undefined;
  try {
    if (!process.argv.includes('--fixture'))
      throw new Error('Provide explicit production settings or use the disposable fixture');
    fixture = await createFixture();
    console.log(JSON.stringify(await runSoapExample(fixture.settings, '0007', 'test')));
  } catch {
    console.error('The SOAP example failed');
    process.exitCode = 1;
  } finally {
    await fixture?.close();
  }
}
