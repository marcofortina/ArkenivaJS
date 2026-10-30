// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import validator from 'validator';
import ipaddr from 'ipaddr.js';
import { Ajv } from 'ajv';
import { nativeIdentifiers } from './identifiers-workload.mjs';

export const validationFixture = Object.freeze({
  email: 'Workload@BENCH.EXAMPLE.INVALID',
  url: 'https://bench.example.invalid/orders?view=fixture',
  ipv4: '192.0.2.25',
  ipv6: '2001:db8::25',
  uuid: 'a47ac10b-58cc-4372-a567-0e02b2c3d479',
  document: Object.freeze({ quantity: 2, active: true }),
  invalidDocument: Object.freeze({ quantity: '2', active: true }),
});
export const validationPolicy = Object.freeze({
  schemes: Object.freeze(['https:']),
  allowedHosts: Object.freeze(['bench.example.invalid']),
  denyPrivateNetworks: true,
});
export const validationSettings = Object.freeze({
  schemas: {
    shape: {
      type: 'object',
      properties: { quantity: { type: 'integer' }, active: { type: 'boolean' } },
      required: ['quantity', 'active'],
      additionalProperties: false,
    },
  },
  policy: { maxConcurrent: 8, timeoutMs: 5000, maxInputBytes: 65536, maxOutputBytes: 65536 },
});
const nativeSchemaError = 'The native fixture does not satisfy its schema';

/** Bare upstream calls use the same fixed ASCII/IP/host/schema corpus; framework snapshot/error/lifecycle work remains additional. */
export function nativeValidation() {
  const ajv = new Ajv({
    strict: true,
    allErrors: false,
    ownProperties: true,
    coerceTypes: false,
    useDefaults: false,
    removeAdditional: false,
    messages: false,
    logger: false,
  });
  const schema = ajv.compile(validationSettings.schemas.shape),
    ids = nativeIdentifiers();
  return Object.freeze({
    email(input) {
      if (
        typeof input !== 'string' ||
        Buffer.byteLength(input) > 254 ||
        /[\u0080-\u{10ffff}]/u.test(input)
      )
        return { valid: false };
      const at = input.lastIndexOf('@'),
        domain = domainToASCII(input.slice(at + 1)),
        normalized = input.slice(0, at + 1) + domain.toLowerCase();
      const valid =
        at >= 1 &&
        domain.length > 0 &&
        Buffer.byteLength(normalized) <= 254 &&
        validator.isEmail(normalized, {
          allow_utf8_local_part: false,
          require_tld: true,
          allow_ip_domain: false,
          allow_display_name: false,
        });
      return valid ? { valid: true, value: normalized } : { valid: false };
    },
    url(input) {
      if (
        typeof input !== 'string' ||
        [...input].some((value) => value.charCodeAt(0) < 32 || value.charCodeAt(0) === 127)
      )
        return { valid: false };
      try {
        const value = new URL(input),
          valid =
            input.startsWith('https://') &&
            value.protocol === 'https:' &&
            value.hostname === validationPolicy.allowedHosts[0] &&
            !value.username &&
            !value.password;
        return valid ? { valid: true, value } : { valid: false };
      } catch {
        return { valid: false };
      }
    },
    ip(input) {
      if (typeof input !== 'string' || input.length > 45 || input.includes('%') || !isIP(input))
        return { valid: false };
      const value = ipaddr.parse(input);
      if (value instanceof ipaddr.IPv6 && value.isIPv4MappedAddress()) return { valid: false };
      return { valid: true, value: value.toString() };
    },
    uuid(input, requested) {
      const valid = ids.isUuid(input, requested);
      return {
        valid,
        ...(valid ? { value: input } : {}),
      };
    },
    assertSchema(input, schemaId) {
      if (schemaId !== 'shape') throw new Error('The native fixture schema is unavailable');
      if (!schema(input)) throw new Error(nativeSchemaError);
    },
  });
}

export function validationWorkload(service, fixture) {
  return Object.freeze({
    email: () => service.email(fixture.email).valid,
    url: () => service.url(fixture.url, validationPolicy).valid,
    ipv4: () => service.ip(fixture.ipv4).valid,
    ipv6: () => service.ip(fixture.ipv6).valid,
    uuid: () => service.uuid(fixture.uuid, 4).valid,
    schema: () => service.assertSchema(fixture.document, 'shape'),
    denyEmail: () => service.email('invalid-email').valid,
    denyIp: () => service.ip('999.1.2.3').valid,
    denySchema: () => {
      try {
        service.assertSchema(fixture.invalidDocument, 'shape');
      } catch (error) {
        if (error?.code === 'EK_VALIDATION_INVALID' || error?.message === nativeSchemaError)
          return true;
        throw error;
      }
      throw new Error('The invalid schema fixture was accepted');
    },
  });
}

/** Compare semantic outcomes on fixed inert inputs, not the framework's additional safe error object shape. */
export function verifyValidation(service, fixture) {
  assert.equal(service.email(fixture.email).value, 'Workload@bench.example.invalid');
  assert.equal(service.url(fixture.url, validationPolicy).value.href, fixture.url);
  assert.equal(service.ip(fixture.ipv4).value, fixture.ipv4);
  assert.equal(service.ip(fixture.ipv6).value, fixture.ipv6);
  assert.equal(service.uuid(fixture.uuid, 4).valid, true);
  assert.equal(service.uuid(fixture.uuid, 7).valid, false);
  assert.equal(service.email('invalid-email').valid, false);
  assert.equal(service.email('member@éxample.invalid').valid, false);
  for (const url of [
    'http://bench.example.invalid/',
    'https://user:password@bench.example.invalid/',
    'https://foreign.invalid/',
    'https://127.0.0.1/',
    'not-a-url',
  ])
    assert.equal(service.url(url, validationPolicy).valid, false);
  for (const ip of ['999.1.2.3', '::ffff:192.0.2.25', 'fe80::1%eth0'])
    assert.equal(service.ip(ip).valid, false);
  assert.doesNotThrow(() => service.assertSchema(fixture.document, 'shape'));
  assert.throws(() => service.assertSchema(fixture.invalidDocument, 'shape'));
  return { checkedCases: 18, positiveFamilies: 6, invalidInputsRejected: true };
}
