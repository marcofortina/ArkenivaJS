// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** Strict SemVer syntax used for service and plugin metadata. */
export const SEMVER_PATTERN =
  '^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?![\\s\\S])';

const positiveInteger = { type: 'integer', minimum: 1, maximum: 2_147_483_647 };
const object = (properties: Record<string, unknown>, required: string[] = []) => ({
  type: 'object',
  additionalProperties: false,
  properties,
  required,
});
const string = { type: 'string', minLength: 1 };
const driver = { enum: ['postgresql', 'mysql', 'mariadb', 'oracle', 'redis', 'etcd', 'mongodb'] };

/** EK-CONF-001: normative root data schema; executable plugin objects are checked separately. */
export const APPLICATION_SCHEMA = object(
  {
    service: object(
      {
        name: { type: 'string', pattern: '^[a-z][a-z0-9-]{0,62}(?![\\s\\S])' },
        version: { type: 'string', pattern: SEMVER_PATTERN },
        environment: { enum: ['development', 'test', 'production'] },
      },
      ['name', 'version', 'environment'],
    ),
    http: {
      oneOf: [
        object(
          {
            protocol: { const: 'http' },
            host: string,
            port: { type: 'integer', minimum: 0, maximum: 65535 },
            requestTimeoutMs: positiveInteger,
          },
          ['host', 'port'],
        ),
        object(
          {
            protocol: { const: 'https' },
            host: string,
            port: { type: 'integer', minimum: 0, maximum: 65535 },
            requestTimeoutMs: positiveInteger,
            http2: { type: 'boolean' },
            tls: object(
              {
                certificateFile: string,
                privateKeyFile: string,
                caFile: string,
                privateKeyPassphraseEnv: { type: 'string', pattern: '^[A-Z_][A-Z0-9_]*$' },
                minVersion: { enum: ['TLSv1.2', 'TLSv1.3'] },
                clientCertificate: { enum: ['none', 'required'] },
              },
              ['certificateFile', 'privateKeyFile'],
            ),
          },
          ['protocol', 'host', 'port', 'tls'],
        ),
      ],
    },
    logging: object(
      { level: { enum: ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent'] } },
      ['level'],
    ),
    telemetry: object(
      {
        mode: { enum: ['off', 'minimal', 'standard', 'detailed'] },
        samplingRatio: { type: 'number', minimum: 0, maximum: 1 },
      },
      ['mode'],
    ),
    metering: object(
      {
        enabled: { type: 'boolean' },
        queueCapacity: { type: 'integer', minimum: 1, maximum: 1_000_000 },
        exporter: { enum: ['jsonl', 'http', 'otlp'] },
        path: string,
        endpoint: string,
      },
      ['enabled'],
    ),
    security: object(
      {
        issuer: string,
        audience: string,
        tenantClaim: string,
        algorithms: { type: 'array', minItems: 1, uniqueItems: true, items: string },
      },
      ['issuer', 'audience'],
    ),
    databases: {
      type: 'object',
      propertyNames: { pattern: '^[a-z][a-z0-9_-]{0,62}$' },
      additionalProperties: object(
        {
          driver,
          connectionStringEnv: { type: 'string', pattern: '^[A-Z_][A-Z0-9_]*$' },
          endpoints: { type: 'array', minItems: 1, uniqueItems: true, items: string },
          poolMin: { type: 'integer', minimum: 0 },
          poolMax: positiveInteger,
        },
        ['driver'],
      ),
    },
  },
  ['service'],
);
