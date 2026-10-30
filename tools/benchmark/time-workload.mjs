// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Temporal } from '@js-temporal/polyfill';

export const timeFixture = Object.freeze({
  instant: '2024-02-29T12:34:56.123456789+01:00',
  transition: '2026-03-28T11:00:00Z',
  zone: 'Europe/Rome',
  locale: 'en-GB',
});
export const timeSettings = Object.freeze({
  allowedZones: Object.freeze(['UTC', 'Europe/Rome', 'America/New_York']),
});
export const timeFormat = Object.freeze({ dateStyle: 'full', timeStyle: 'long', hourCycle: 'h23' });
const value = (zoned) => Object.freeze({ iso: zoned.toString(), zone: zoned.timeZoneId });

/** Bare Temporal/Intl operations accept only the fixed valid comparison corpus. */
export function nativeTime() {
  return {
    parseInstant: (text) => Temporal.Instant.from(text).toString(),
    toZoned: (instant, zone) => value(Temporal.Instant.from(instant).toZonedDateTimeISO(zone)),
    add(zoned, duration) {
      return value(Temporal.ZonedDateTime.from(zoned.iso).add({ hours: duration.hours }));
    },
    format(zoned, locale, options) {
      const time = Temporal.ZonedDateTime.from(zoned.iso);
      return new Intl.DateTimeFormat(locale, { ...options, timeZone: zoned.zone }).format(
        new Date(time.epochMilliseconds),
      );
    },
  };
}

export function verifyTime(service, fixture = timeFixture) {
  assert.equal(service.parseInstant(fixture.instant), '2024-02-29T11:34:56.123456789Z');
  const before = service.toZoned(service.parseInstant(fixture.transition), fixture.zone);
  assert.equal(before.iso, '2026-03-28T12:00:00+01:00[Europe/Rome]');
  assert.equal(before.zone, fixture.zone);
  assert.equal(Object.isFrozen(before), true);
  const after = service.add(before, { hours: 24 }, 'reject');
  assert.equal(after.iso, '2026-03-29T13:00:00+02:00[Europe/Rome]');
  assert.equal(Object.isFrozen(after), true);
  const formatted = service.format(after, fixture.locale, timeFormat);
  assert.equal(typeof formatted, 'string');
  assert.ok(formatted.length > 0);
  const us = service.toZoned(service.parseInstant('2026-03-07T17:00:00Z'), 'America/New_York');
  assert.equal(
    service.add(us, { hours: 24 }, 'reject').iso,
    '2026-03-08T13:00:00-04:00[America/New_York]',
  );
  return { checkedCases: 8, nanosecondsPreserved: true, elapsedDstTransitionsVerified: 2 };
}

export function timeWorkload(service, fixture = timeFixture) {
  const instant = service.parseInstant(fixture.instant),
    zoned = service.toZoned(service.parseInstant(fixture.transition), fixture.zone);
  return {
    parseInstant: () => service.parseInstant(fixture.instant),
    toZoned: () => service.toZoned(instant, fixture.zone),
    addElapsedHours: () => service.add(zoned, { hours: 24 }, 'reject'),
    format: () => service.format(zoned, fixture.locale, timeFormat),
  };
}
