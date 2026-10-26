// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import { createTimeService, dataTimePlugin, TIME_CAPABILITY } from '../../dist/index.js';
import type { TimeService } from '../../dist/index.js';

const settings = () => ({ allowedZones: ['UTC', 'Europe/Rome', 'America/New_York'] });
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
test('Instant parsing delegates calendar/offset validity and preserves nanoseconds in normalized UTC', () => {
  const time = createTimeService(settings());
  assert.equal(
    time.parseInstant('2024-02-29T12:34:56.123456789+01:00'),
    '2024-02-29T11:34:56.123456789Z',
  );
  assert.equal(time.parseInstant('2026-10-26T12:00:00.000Z'), '2026-10-26T12:00:00Z');
  for (const value of [
    '2023-02-29T12:00:00Z',
    '2026-13-01T00:00:00Z',
    '2026-01-01T24:00:00Z',
    '2026-01-01T00:00:60Z',
    '2026-01-01T00:00:00+24:00',
    '2026-01-01T00:00:00',
    '2026-01-01',
    '2026-01-01 00:00:00Z',
    '2026-01-01T00:00Z',
    '2026-01-01T00:00:00Z[UTC]',
    '2026-01-01T00:00:00.1234567890Z',
    '2026-01-01T00:00:00Z\n',
    null,
    {},
    'x'.repeat(65),
  ])
    assert.throws(() => time.parseInstant(value as never), code('EK_TIME_INVALID'));
  assert.throws(
    () => time.toZoned('2026-01-01T01:00:00+01:00' as never, 'UTC'),
    code('EK_TIME_INVALID'),
  );
});
test('Calendar days differ from 24 elapsed hours across the Europe/Rome spring transition', () => {
  const time = createTimeService(settings()),
    before = time.toZoned(time.parseInstant('2026-03-28T11:00:00Z'), 'Europe/Rome');
  assert.equal(before.iso, '2026-03-28T12:00:00+01:00[Europe/Rome]');
  assert.equal(
    time.add(before, { days: 1 }, 'reject').iso,
    '2026-03-29T12:00:00+02:00[Europe/Rome]',
  );
  assert.equal(
    time.add(before, { hours: 24 }, 'reject').iso,
    '2026-03-29T13:00:00+02:00[Europe/Rome]',
  );
  assert.ok(Object.isFrozen(before));
});
test('Rome DST gaps use explicit reject/earlier/later/compatible policies through Temporal', () => {
  const time = createTimeService(settings()),
    before = time.toZoned(time.parseInstant('2026-03-28T01:30:00Z'), 'Europe/Rome');
  assert.throws(() => time.add(before, { days: 1 }, 'reject'), code('EK_TIME_AMBIGUOUS'));
  assert.equal(
    time.add(before, { days: 1 }, 'earlier').iso,
    '2026-03-29T01:30:00+01:00[Europe/Rome]',
  );
  assert.equal(
    time.add(before, { days: 1 }, 'later').iso,
    '2026-03-29T03:30:00+02:00[Europe/Rome]',
  );
  assert.deepEqual(
    time.add(before, { days: 1 }, 'compatible'),
    time.add(before, { days: 1 }, 'later'),
  );
});
test('Rome DST folds select distinct instants and elapsed arithmetic preserves the existing fold offset', () => {
  const time = createTimeService(settings()),
    before = time.toZoned(time.parseInstant('2026-10-24T00:30:00Z'), 'Europe/Rome');
  assert.throws(() => time.add(before, { days: 1 }, 'reject'), code('EK_TIME_AMBIGUOUS'));
  const earlier = time.add(before, { days: 1 }, 'earlier'),
    later = time.add(before, { days: 1 }, 'later');
  assert.equal(earlier.iso, '2026-10-25T02:30:00+02:00[Europe/Rome]');
  assert.equal(later.iso, '2026-10-25T02:30:00+01:00[Europe/Rome]');
  assert.deepEqual(time.add(before, { days: 1 }, 'compatible'), earlier);
  assert.deepEqual(time.add(later, {}, 'reject'), later);
  assert.deepEqual(time.add(earlier, { hours: 1 }, 'reject'), later);
});
test('US DST, leap days and constrained month arithmetic retain native calendar semantics', () => {
  const time = createTimeService(settings()),
    gap = time.toZoned(time.parseInstant('2026-03-07T07:30:00Z'), 'America/New_York'),
    fold = time.toZoned(time.parseInstant('2026-10-31T05:30:00Z'), 'America/New_York');
  assert.throws(() => time.add(gap, { days: 1 }, 'reject'), code('EK_TIME_AMBIGUOUS'));
  assert.equal(
    time.add(gap, { days: 1 }, 'later').iso,
    '2026-03-08T03:30:00-04:00[America/New_York]',
  );
  assert.throws(() => time.add(fold, { days: 1 }, 'reject'), code('EK_TIME_AMBIGUOUS'));
  assert.equal(
    time.add(fold, { days: 1 }, 'later').iso,
    '2026-11-01T01:30:00-05:00[America/New_York]',
  );
  const leap = time.toZoned(time.parseInstant('2024-02-28T12:00:00Z'), 'UTC');
  assert.equal(time.add(leap, { days: 1 }, 'reject').iso, '2024-02-29T12:00:00+00:00[UTC]');
  assert.equal(time.add(leap, { days: 2 }, 'reject').iso, '2024-03-01T12:00:00+00:00[UTC]');
  assert.equal(time.add(leap, { days: -1 }, 'reject').iso, '2024-02-27T12:00:00+00:00[UTC]');
  const january = time.toZoned(time.parseInstant('2024-01-31T12:00:00Z'), 'UTC');
  assert.equal(time.add(january, { months: 1 }, 'reject').iso, '2024-02-29T12:00:00+00:00[UTC]');
});
test('Formatting uses only an explicit supported locale/zone and validates runtime Intl options', () => {
  const time = createTimeService(settings()),
    zoned = time.toZoned(time.parseInstant('2026-03-29T01:30:00Z'), 'Europe/Rome');
  const output = time.format(zoned, 'en-GB', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  });
  assert.ok(output.includes('29/03/2026'));
  assert.ok(output.includes('03:30'));
  assert.ok(time.format(zoned, 'it-IT', { month: 'long' }).includes('marzo'));
  assert.throws(() => time.format(zoned, 'en-GB', { timeZone: 'UTC' }), code('EK_TIME_ZONE'));
  for (const locale of ['', 'zz', 'not_a_locale', {}, null, 'x'.repeat(129)])
    assert.throws(() => time.format(zoned, locale as never), code('EK_TIME_INVALID'));
  for (const options of [
    null,
    { extra: true },
    { hour12: 'true' },
    { year: {} },
    { fractionalSecondDigits: 0 },
    { fractionalSecondDigits: 4 },
    { month: 'invalid' },
    { dateStyle: 'full', year: 'numeric' },
  ])
    assert.throws(() => time.format(zoned, 'en-GB', options as never), code('EK_TIME_INVALID'));
});
test('Captured zone policy and runtime structure reject forged dates, accessors and unsafe configuration', () => {
  const zones = ['UTC'],
    time = createTimeService({ allowedZones: zones });
  zones.push('Europe/Rome');
  const instant = time.parseInstant('2026-01-01T00:00:00Z'),
    zoned = time.toZoned(instant, 'UTC');
  for (const zone of ['Europe/Rome', '+01:00', 'Invalid/Zone', null, {}])
    assert.throws(() => time.toZoned(instant, zone as never), code('EK_TIME_ZONE'));
  let invoked = 0;
  const getter = Object.defineProperty({}, 'iso', {
    get() {
      invoked++;
      return zoned.iso;
    },
  });
  for (const input of [
    null,
    {},
    getter,
    { ...zoned, zone: 'Europe/Rome' },
    { ...zoned, extra: true },
    { iso: '2026-01-01T00:00:00+03:00[UTC]', zone: 'UTC' },
    { iso: '2026-01-01T00:00:00+00:00[UTC][u-ca=hebrew]', zone: 'UTC' },
  ])
    assert.throws(() => time.add(input as never, {}, 'reject'));
  for (const duration of [
    null,
    [],
    { minutes: 1 },
    { hours: null },
    { days: 0.5 },
    { hours: Infinity },
    { months: 1, days: -1 },
    { days: Number.MAX_SAFE_INTEGER },
  ])
    assert.throws(() => time.add(zoned, duration as never, 'reject'), code('EK_TIME_INVALID'));
  for (const policy of [undefined, null, 'automatic', {}])
    assert.throws(() => time.add(zoned, {}, policy as never), code('EK_TIME_INVALID'));
  assert.equal(invoked, 0);
  for (const config of [
    null,
    {},
    { allowedZones: [] },
    { allowedZones: ['UTC', 'UTC'] },
    { allowedZones: ['Invalid/Zone'] },
    { allowedZones: ['+01:00'] },
    { allowedZones: new Array(1) },
    { allowedZones: ['UTC'], extra: true },
  ])
    assert.throws(() => createTimeService(config as never), code('EK_CONFIG_INVALID'));
  const privateProxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new KitError({ code: 'EK_TIME_ZONE', message: 'private-runtime-value' });
      },
    },
  );
  assert.throws(
    () => time.add(privateProxy as never, {}, 'reject'),
    (error) => {
      assert.ok(error instanceof KitError);
      assert.ok(!JSON.stringify(error.toSafeJSON()).includes('private-runtime-value'));
      return true;
    },
  );
});
test('Reused time capabilities retain isolated lifetimes and never mutate process timezone', async () => {
  const original = process.env.TZ,
    plugin = dataTimePlugin(settings()),
    config = {
      service: { name: 'time-fixture', version: '1.0.0', environment: 'test' as const },
      plugins: [plugin],
    };
  const a = await createApplication(config),
    b = await createApplication(config);
  try {
    await a.start();
    await b.start();
    const first = a.resolve<TimeService>(TIME_CAPABILITY),
      second = b.resolve<TimeService>(TIME_CAPABILITY);
    const instant = first.parseInstant('2026-01-01T00:00:00Z'),
      zoned = first.toZoned(instant, 'UTC');
    await a.stop();
    for (const call of [
      () => first.parseInstant(instant),
      () => first.toZoned(instant, 'UTC'),
      () => first.add(zoned, {}, 'reject'),
      () => first.format(zoned, 'en-GB'),
    ])
      assert.throws(call, code('EK_RESOURCE_CLOSED'));
    assert.deepEqual(second.toZoned(instant, 'UTC'), zoned);
    assert.equal(process.env.TZ, original);
  } finally {
    await a.stop();
    await b.stop();
  }
});
