// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import type { GrpcService } from '@arkenivajs/grpc';
import { createFixture } from './fixture.js';

/** Use an application-owned channel and an assertion issued for the configured RPC audience. */
export async function echo(service: GrpcService, authorization: string, value: string) {
  const client = service.client('Echo'),
    metadata = { authorization };
  const response = await client.unary<{ value: string; sequence: string }>(
    'Bounce',
    { value, sequence: '9223372036854775807' },
    { metadata, timeoutMs: 2000 },
  );
  const sequence: string[] = [];
  for await (const item of client.serverStream<{ sequence: string }>(
    'Watch',
    { value },
    { metadata, timeoutMs: 2000 },
  ))
    sequence.push(item.sequence);
  return { value: response.value, exactInteger: response.sequence, sequence };
}
export async function runGrpcExample() {
  const fixture = await createFixture();
  try {
    return await echo(fixture.service, await fixture.bearer(), 'native-protobuf');
  } finally {
    await fixture.close();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (!process.argv.includes('--fixture'))
      throw new Error('Use explicit application configuration or the disposable fixture');
    console.log(JSON.stringify(await runGrpcExample()));
  } catch {
    console.error('The gRPC example failed');
    process.exitCode = 1;
  }
}
