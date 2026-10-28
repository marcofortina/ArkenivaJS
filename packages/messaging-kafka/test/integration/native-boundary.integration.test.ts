// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

test('Actual native offset conversions preserve signed 64-bit integers before promisified commit conversion', async () => {
  const require = createRequire(import.meta.url);
  const manifest = require.resolve('@confluentinc/kafka-javascript/package.json');
  const sdk = dirname(manifest),
    local = createRequire(manifest);
  require('@confluentinc/kafka-javascript');
  assert.equal(
    (local('./librdkafka.js') as { arkenivajsNativeCompatibilityVersion?: number })
      .arkenivajsNativeCompatibilityVersion,
    2,
  );
  const directory = await mkdtemp(join(tmpdir(), 'owned-kafka-offset-'));
  try {
    const binary = join(sdk, 'build/Release/confluent-kafka-javascript.node');
    const output = join(directory, 'boundary.node');
    const source = resolve(import.meta.dirname, '../../test/native/offset-boundary.cc');
    const includes = [
      resolve(dirname(process.execPath), '../include/node'),
      dirname(local.resolve('nan')),
      sdk,
      join(sdk, 'deps/librdkafka/src'),
      join(sdk, 'deps/librdkafka/src-cpp'),
    ];
    execFileSync(
      'g++',
      [
        '-std=c++20',
        '-shared',
        '-fPIC',
        source,
        ...includes.flatMap((path) => ['-I', path]),
        binary,
        '-Wl,-rpath,' + dirname(binary),
        '-o',
        output,
      ],
      { timeout: 60000, stdio: 'pipe' },
    );
    const native = require(output) as {
      roundTrip(input: { offset: bigint }): { offset: number; offsetString: string };
    };
    const common = local('./lib/kafkajs/_common.js') as {
      exactOffset(value: unknown): bigint;
      topicPartitionOffsetToRdKafka(value: { topic: string; partition: number; offset?: string }): {
        offset?: bigint;
      };
      topicPartitionOffsetMetadataToRdKafka(value: {
        topic: string;
        partition: number;
        offset: string;
      }): { offset: bigint };
    };
    assert.equal(
      common.topicPartitionOffsetToRdKafka({ topic: 'owned-native-boundary', partition: 0 }).offset,
      undefined,
    );
    assert.equal(
      common.topicPartitionOffsetToRdKafka({
        topic: 'owned-native-boundary',
        partition: 0,
        offset: '0',
      }).offset,
      0n,
    );
    for (const value of [
      0n,
      9007199254740991n,
      9007199254740992n,
      9007199254740993n,
      9223372036854775807n,
    ]) {
      const nativeValue = native.roundTrip({ offset: value });
      assert.equal(nativeValue.offsetString, value.toString());
      assert.equal(common.exactOffset(nativeValue.offsetString), value);
      const commit = common.topicPartitionOffsetMetadataToRdKafka({
        topic: 'owned-native-boundary',
        partition: 0,
        offset: value.toString(),
      });
      assert.equal(commit.offset, value);
      assert.equal(native.roundTrip(commit).offsetString, value.toString());
    }
    const publicBoundary = native.roundTrip({ offset: 9007199254740993n });
    assert.notEqual(String(publicBoundary.offset), publicBoundary.offsetString);
    assert.throws(() => common.exactOffset(publicBoundary.offset));
    for (const invalid of [NaN, Infinity, 0.5, '01', '9223372036854775808', {}, null])
      assert.throws(() => common.exactOffset(invalid));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
