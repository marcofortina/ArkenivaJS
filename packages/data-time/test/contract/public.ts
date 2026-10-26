// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createTimeService, dataTimePlugin } from '../../dist/index.js';
import type { TimeService, ZonedValue } from '../../dist/index.js';

/** Check public contracts without executing negative requests. */
export function publicContract(time: TimeService, zoned: ZonedValue) {
  createTimeService({ allowedZones: ['UTC'] });
  dataTimePlugin({ allowedZones: ['UTC'] });
  // @ts-expect-error A caller cannot supply an unparsed plain string as a branded instant.
  time.toZoned('2026-01-01T00:00:00Z', 'UTC');
  // @ts-expect-error Calendar arithmetic always requires explicit DST disambiguation.
  time.add(zoned, { days: 1 });
  // @ts-expect-error Only the declared duration components are exposed.
  time.add(zoned, { minutes: 30 }, 'reject');
  // @ts-expect-error Zone metadata is immutable.
  zoned.zone = 'Europe/Rome';
  return time.format(time.toZoned(time.parseInstant('2026-01-01T00:00:00Z'), 'UTC'), 'en-GB');
}
