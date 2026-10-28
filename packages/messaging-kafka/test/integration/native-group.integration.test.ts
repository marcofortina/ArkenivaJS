// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

test(
  'Actual native descriptions preserve denied-group errors and null assignors without crashing',
  { timeout: 15000 },
  async () => {
    assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
    const directory = process.env.ARKENIVA_KAFKA_SECRETS;
    assert.ok(directory, 'An owned private TLS/SASL fixture is required');
    const credential = JSON.parse(
      await readFile(join(directory, 'fixture-denied.json'), 'utf8'),
    ) as { username: string; password: string };
    const { KafkaJS } = createRequire(import.meta.url)(
      '@confluentinc/kafka-javascript',
    ) as typeof import('@confluentinc/kafka-javascript');
    const logger: import('@confluentinc/kafka-javascript').KafkaJS.Logger = {
      info() {},
      error() {},
      warn() {},
      debug() {},
      namespace() {
        return this;
      },
      setLogLevel() {},
    };
    const admin = new KafkaJS.Kafka({
      log_level: 0,
      'security.protocol': 'sasl_ssl',
      'ssl.ca.pem': await readFile(join(directory, 'ca.pem'), 'utf8'),
      'enable.ssl.certificate.verification': true,
      'ssl.endpoint.identification.algorithm': 'https',
      'sasl.mechanisms': 'PLAIN',
      'sasl.username': credential.username,
      'sasl.password': credential.password,
      kafkaJS: { brokers: ['127.0.0.1:19094'], logger, logLevel: 0 },
    }).admin();
    const groupId = 'owned-secure-denied-' + randomUUID();
    try {
      await admin.connect();
      const result = await admin.describeGroups([groupId], { timeout: 5000 });
      assert.equal(result.groups.length, 1);
      const group = result.groups[0]!;
      assert.equal(group.groupId, groupId);
      assert.ok(
        group.error && group.error.code !== 0,
        'Denied group metadata must retain its explicit native error',
      );
      assert.deepEqual(group.members, []);
      assert.equal(group.protocol, null);
      assert.equal(group.partitionAssignor, null);
    } finally {
      await admin.disconnect();
    }
  },
);
