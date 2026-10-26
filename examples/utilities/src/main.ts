// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createIdentifiersService } from '@arkenivajs/data-identifiers';
import { createValidationService } from '@arkenivajs/data-validation';
import { createTimeService } from '@arkenivajs/data-time';
import { createCsvService } from '@arkenivajs/data-csv';

/** Exercise public utilities without an application or external services. */
export async function runUtilities() {
  const ids = createIdentifiersService({ allowVersions: [4, 7] }),
    v4 = ids.uuidV4(),
    v7 = ids.uuidV7(),
    validation = createValidationService({
      schemas: {
        order: {
          type: 'object',
          additionalProperties: false,
          required: ['id'],
          properties: { id: { type: 'integer' } },
        },
      },
      policy: { maxConcurrent: 1, timeoutMs: 1000 },
    });
  validation.assertSchema({ id: 7 }, 'order');
  const time = createTimeService({ allowedZones: ['UTC', 'Europe/Rome'] }),
    rome = time.toZoned(time.parseInstant('2026-03-28T11:00:00Z'), 'Europe/Rome'),
    calendarDay = time.add(rome, { days: 1 }, 'reject'),
    elapsedDay = time.add(rome, { hours: 24 }, 'reject');
  const email = validation.email('User@EXAMPLE.ORG'),
    ip = validation.ip('2001:0db8:0000:0000:0000:0000:0000:0001');
  const csv = createCsvService({
      defaults: { hasHeader: true },
      policy: { maxConcurrent: 1, timeoutMs: 1000 },
    }),
    rows = [];
  for await (const row of csv.parse(Buffer.from('id,note\n001,"hello, world"\n002,value\n')))
    rows.push(row);
  const chunks: Uint8Array[] = [];
  for await (const chunk of csv.stringify(rows)) chunks.push(chunk);
  const csvOutput = Buffer.concat(chunks).toString('utf8');
  return Object.freeze({
    v4Version: ids.parseUuid(v4).version,
    v7Version: ids.parseUuid(v7).version,
    malformedRejected: !ids.isUuid('invalid'),
    canonicalPolicyEnforced: !ids.isUuid(v4.toUpperCase()),
    emailNormalized: email.valid && email.value === 'User@example.org',
    ipNormalized: ip.valid && ip.value === '2001:db8::1',
    privateUrlRejected: !validation.url('https://127.0.0.1', { schemes: ['https:'] }).valid,
    schemaAccepted: true,
    dstCalendarPreserved: calendarDay.iso === '2026-03-29T12:00:00+02:00[Europe/Rome]',
    elapsedHoursPreserved: elapsedDay.iso === '2026-03-29T13:00:00+02:00[Europe/Rome]',
    csvTextPreserved: rows[0]?.columns?.id === '001' && csvOutput.includes('001,"hello, world"'),
    csvRoundtripRows: rows.length,
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(await runUtilities()));
