import { KitError } from '@arkenivajs/core';
import type { MeteringEvent } from '@arkenivajs/core';
import { compileSchema, copyData, freezeData, SEMVER_PATTERN } from '@arkenivajs/core/support';

const text = (maxLength: number) => ({ type: 'string', minLength: 1, maxLength });
const mapping = (properties: Record<string, unknown>, required = Object.keys(properties)) => ({
  type: 'object',
  properties,
  required,
  additionalProperties: false,
});
const timestamp = {
  type: 'string',
  pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3,9}Z$',
};
const properties = {
  schemaVersion: { const: '1.0.0' },
  eventId: {
    type: 'string',
    pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
  },
  tenantId: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' },
  operationId: text(128),
  parentOperationId: text(128),
  requestId: text(128),
  traceId: { type: 'string', pattern: '^[0-9a-f]{32}$' },
  service: { type: 'string', pattern: '^[a-z][a-z0-9-]{0,62}$' },
  serviceVersion: { type: 'string', pattern: SEMVER_PATTERN },
  environment: { enum: ['test', 'development', 'production'] },
  instanceId: text(128),
  operation: text(256),
  startedAt: timestamp,
  endedAt: timestamp,
  durationMs: { type: 'number', minimum: 0 },
  status: { enum: ['ok', 'error', 'aborted', 'unknown'] },
  k8s: mapping({ namespace: text(253), pod: text(253), container: text(253), node: text(253) }, []),
  counters: {
    type: 'object',
    maxProperties: 128,
    propertyNames: { pattern: '^[a-z][a-z0-9_.]{1,79}$' },
    additionalProperties: mapping({
      unit: { enum: ['bytes', 'operations', 'milliseconds', 'items'] },
      source: { enum: ['observed', 'derived'] },
      value: { type: 'number', minimum: 0 },
    }),
  },
  quality: mapping({
    complete: { type: 'boolean' },
    droppedChildCount: { type: 'integer', minimum: 0 },
    missing: {
      type: 'array',
      uniqueItems: true,
      maxItems: 6,
      items: {
        enum: [
          'exporter_unavailable',
          'driver_bytes_unavailable',
          'span_not_instrumented',
          'meter_queue_overflow',
          'downstream_unobserved',
          'aborted_before_close',
        ],
      },
    },
  }),
};
const optional = new Set(['parentOperationId', 'requestId', 'traceId', 'k8s']);
const validate = compileSchema(
  mapping(
    properties,
    Object.keys(properties).filter((key) => !optional.has(key)),
  ),
);
/** Validate and freeze this producer's event envelope before any transport accepts it. */
export function parseMeteringEvent(input: unknown): MeteringEvent {
  try {
    const event = copyData(input) as MeteringEvent;
    const safeStrings = (value: unknown): boolean => {
      const clean = (text: string) =>
        [...text].every((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127);
      if (typeof value === 'string') return clean(value);
      if (value && typeof value === 'object')
        return Object.entries(value).every(([key, child]) => clean(key) && safeStrings(child));
      return true;
    };
    if (
      !validate(event) ||
      !safeStrings(event) ||
      Buffer.byteLength(JSON.stringify(event)) > 16_384
    )
      throw new Error('Invalid event structure');
    for (const value of [event.startedAt, event.endedAt]) {
      const date = new Date(value);
      if (
        !Number.isFinite(date.getTime()) ||
        date.toISOString().slice(0, 19) !== value.slice(0, 19)
      )
        throw new Error('Invalid event timestamp');
    }
    if (
      Date.parse(event.startedAt) > Date.parse(event.endedAt) ||
      event.quality.complete !== (event.quality.missing.length === 0) ||
      event.traceId === '0'.repeat(32)
    )
      throw new Error('Inconsistent event metadata');
    return freezeData(event);
  } catch (cause) {
    throw new KitError({
      code: 'EK_METER_EXPORT',
      message: 'Invalid technical metering event',
      cause,
    });
  }
}
