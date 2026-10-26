// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Temporal } from '@js-temporal/polyfill';
import { KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';

/** A normalized UTC instant; runtime consumers still validate branded strings. */
export type InstantValue = string & { readonly __instant: 'ISO8601UTC' };
/** Zoned ISO representation and its explicitly allowed IANA zone. */
export type ZonedValue = Readonly<{ iso: string; zone: string }>;
/** Explicit Temporal policy for missing/repeated local calendar times. */
export type DstDisambiguation = 'reject' | 'earlier' | 'later' | 'compatible';
/** Allowed IANA identifiers are canonicalized and captured at construction. */
export interface DataTimePluginSettings {
  readonly allowedZones: readonly string[];
}
/** Pure calendar/instant operations never read a clock or change the process timezone. */
export interface TimeService {
  /** Parse a strict offset-bearing ISO timestamp and serialize its instant in UTC. */
  parseInstant(text: string): InstantValue;
  /** Convert a validated UTC instant to an explicitly allowed IANA zone. */
  toZoned(instant: InstantValue, ianaZone: string): ZonedValue;
  /** Apply calendar months/days, resolve wall time explicitly, then apply elapsed hours. */
  add(
    zoned: ZonedValue,
    duration: Readonly<{ hours?: number; days?: number; months?: number }>,
    policy: DstDisambiguation,
  ): ZonedValue;
  /** Format using an explicit supported locale and the validated zone. */
  format(zoned: ZonedValue, locale: string, options?: Intl.DateTimeFormatOptions): string;
}
const invalid = () =>
  new KitError({
    code: 'EK_TIME_INVALID',
    message: 'The time value or operation policy is invalid',
  });
const zoneError = () =>
  new KitError({
    code: 'EK_TIME_ZONE',
    message: 'The time zone is invalid or outside the configured policy',
  });
const ambiguous = () =>
  new KitError({
    code: 'EK_TIME_AMBIGUOUS',
    message: 'The calendar result has a missing or repeated local time',
  });
function fields(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  )
    throw invalid();
  const output: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.includes(key)) throw invalid();
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field || !('value' in field)) throw invalid();
    output[key] = field.value;
  }
  return output;
}
function canonicalZone(input: unknown): string {
  try {
    if (typeof input !== 'string' || !/^[A-Za-z][A-Za-z0-9_+/-]{0,127}$/.test(input))
      throw zoneError();
    // Intl resolves IANA aliases without inheriting the host's default zone.
    return new Intl.DateTimeFormat('en-US', { timeZone: input }).resolvedOptions().timeZone;
  } catch {
    throw zoneError();
  }
}
function capture(settings: DataTimePluginSettings): ReadonlySet<string> {
  try {
    const input = fields(settings, ['allowedZones']).allowedZones;
    if (
      !Array.isArray(input) ||
      input.length < 1 ||
      input.length > 256 ||
      Reflect.ownKeys(input).length !== input.length + 1
    )
      throw invalid();
    const allowed = new Set<string>();
    for (let index = 0; index < input.length; index++) {
      const item = Object.getOwnPropertyDescriptor(input, String(index));
      if (!item || !('value' in item)) throw invalid();
      const canonical = canonicalZone(item.value);
      if (allowed.has(canonical)) throw invalid();
      allowed.add(canonical);
    }
    return allowed;
  } catch {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Time settings require distinct valid IANA zones',
    });
  }
}
const formatFields = [
  'localeMatcher',
  'weekday',
  'era',
  'year',
  'month',
  'day',
  'hour',
  'minute',
  'second',
  'timeZoneName',
  'formatMatcher',
  'hour12',
  'timeZone',
  'dateStyle',
  'timeStyle',
  'calendar',
  'dayPeriod',
  'numberingSystem',
  'hourCycle',
  'fractionalSecondDigits',
];
function service(allowed: ReadonlySet<string>, ready: () => void): TimeService {
  const invoke = <T>(operation: () => T): T => {
    ready();
    try {
      return operation();
    } catch (cause) {
      if (cause instanceof KitError && cause.code === 'EK_TIME_ZONE') throw zoneError();
      if (cause instanceof KitError && cause.code === 'EK_TIME_AMBIGUOUS') throw ambiguous();
      throw invalid();
    }
  };
  const zone = (input: unknown) => {
    const name = canonicalZone(input);
    if (!allowed.has(name)) throw zoneError();
    return name;
  };
  const instant = (text: unknown) => {
    // This bounded lexical envelope excludes local times, annotations and leap-second clamping.
    // Calendar validity, offsets, ranges and nanosecond arithmetic remain upstream operations.
    if (
      typeof text !== 'string' ||
      text.length > 64 ||
      !/^(?:\d{4}|[+-]\d{6})-\d{2}-\d{2}T\d{2}:\d{2}:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(
        text,
      )
    )
      throw invalid();
    return Temporal.Instant.from(text);
  };
  const zoned = (value: unknown) => {
    const input = fields(value, ['iso', 'zone']),
      name = zone(input.zone);
    if (typeof input.iso !== 'string' || input.iso.length > 256) throw invalid();
    const parsed = Temporal.ZonedDateTime.from(input.iso, {
      offset: 'reject',
      disambiguation: 'reject',
    });
    if (parsed.calendarId !== 'iso8601' || canonicalZone(parsed.timeZoneId) !== name)
      throw invalid();
    return parsed.withTimeZone(name);
  };
  const value = (time: Temporal.ZonedDateTime): ZonedValue =>
    Object.freeze({ iso: time.toString(), zone: time.timeZoneId });
  return Object.freeze({
    parseInstant(text: string) {
      return invoke(() => instant(text).toString() as InstantValue);
    },
    toZoned(input: InstantValue, name: string) {
      return invoke(() => {
        const parsed = instant(input);
        if (parsed.toString() !== input) throw invalid();
        return value(parsed.toZonedDateTimeISO(zone(name)));
      });
    },
    add(
      input: ZonedValue,
      duration: Readonly<{ hours?: number; days?: number; months?: number }>,
      policy: DstDisambiguation,
    ) {
      return invoke(() => {
        if (!['reject', 'earlier', 'later', 'compatible'].includes(policy)) throw invalid();
        const components = fields(duration, ['hours', 'days', 'months']);
        for (const component of Object.values(components))
          if (component !== undefined && !Number.isSafeInteger(component)) throw invalid();
        const delta = Temporal.Duration.from({
          hours: components.hours === undefined ? 0 : (components.hours as number),
          days: components.days === undefined ? 0 : (components.days as number),
          months: components.months === undefined ? 0 : (components.months as number),
        });
        let current = zoned(input);
        if (delta.days !== 0 || delta.months !== 0) {
          const target = current
            .toPlainDateTime()
            .add({ months: delta.months, days: delta.days }, { overflow: 'constrain' });
          if (policy === 'reject') {
            const earlier = target.toZonedDateTime(current.timeZoneId, {
                disambiguation: 'earlier',
              }),
              later = target.toZonedDateTime(current.timeZoneId, { disambiguation: 'later' });
            if (!earlier.equals(later)) throw ambiguous();
            current = earlier;
          } else current = target.toZonedDateTime(current.timeZoneId, { disambiguation: policy });
        }
        return value(current.add({ hours: delta.hours }));
      });
    },
    format(input: ZonedValue, locale: string, options?: Intl.DateTimeFormatOptions) {
      return invoke(() => {
        const current = zoned(input);
        if (
          typeof locale !== 'string' ||
          locale.length < 1 ||
          locale.length > 128 ||
          Intl.DateTimeFormat.supportedLocalesOf([locale], { localeMatcher: 'lookup' }).length !== 1
        )
          throw invalid();
        const supplied = fields(options === undefined ? {} : options, formatFields);
        for (const [key, item] of Object.entries(supplied)) {
          if (item === undefined) continue;
          if (
            key === 'hour12'
              ? typeof item !== 'boolean'
              : key === 'fractionalSecondDigits'
                ? !Number.isInteger(item) || (item as number) < 1 || (item as number) > 3
                : typeof item !== 'string' || item.length > 128
          )
            throw invalid();
        }
        if (supplied.timeZone !== undefined && zone(supplied.timeZone) !== current.timeZoneId)
          throw zoneError();
        const formatter = new Intl.DateTimeFormat(locale, {
          ...supplied,
          timeZone: current.timeZoneId,
        });
        return formatter.format(new Date(current.epochMilliseconds));
      });
    },
  });
}
/** Construct a pure native-backed facade without a clock, process-global settings or resources. */
export function createTimeService(settings: DataTimePluginSettings): TimeService {
  return service(capture(settings), () => undefined);
}
/** Optional application capability for explicit registration. */
export const TIME_CAPABILITY: unique symbol = Symbol('arkenivajs.time');
/** Register an isolated application-owned time facade. */
export function dataTimePlugin(settings: DataTimePluginSettings): Plugin {
  const allowed = capture(settings),
    instances = new WeakMap<object, { close(): void }>();
  return {
    id: 'data-time',
    version: '0.1.0',
    capabilities: new Set(['time']),
    init(context) {
      let open = true;
      context.provide(
        TIME_CAPABILITY,
        service(allowed, () => {
          if (!open)
            throw new KitError({
              code: 'EK_RESOURCE_CLOSED',
              message: 'The time service is closed',
            });
        }),
      );
      instances.set(context, {
        close() {
          open = false;
        },
      });
    },
    close(context) {
      instances.get(context)?.close();
      instances.delete(context);
    },
  };
}
