// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { managedService } from '../../dist/service.js';
import { settings } from '../../dist/settings.js';
import type { KafkaRecord, KafkaPublicationReceipt } from '../../dist/contracts.js';
import type { KafkaJS } from '@confluentinc/kafka-javascript';

function fixture() {
  assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
  const broker = process.env.ARKENIVA_KAFKA_BROKER!;
  assert.match(broker, /^127\.0\.0\.1:[0-9]{1,5}$/);
  const reports: string[] = [];
  const owner = managedService(
    settings({
      clusters: [
        {
          name: 'owned',
          brokers: [broker],
          clientId: 'owned-consumer-' + randomUUID(),
          topics: ['orders.created'],
          maxBufferedMessages: 8,
          maxMessageBytes: 262144,
          acks: 'all',
          idempotentProducer: true,
        },
      ],
    }),
    new AbortController().signal,
    () => true,
    'test',
    (code) => reports.push(code),
  );
  return { ...owner, reports };
}
const config = (groupId: string) => ({
  cluster: 'owned',
  topics: ['orders.created'],
  groupId,
  offsetReset: 'earliest' as const,
});
const publication = (key: string) => ({
  cluster: 'owned',
  topic: 'orders.created',
  key: Buffer.from(key),
  value: Buffer.from([0, 128, 255]),
});
function gate<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function observed<T>(promise: Promise<T>, reports: readonly string[]): Promise<T> {
  let timer!: ReturnType<typeof globalThis.setTimeout>;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = globalThis.setTimeout(
          () => reject(new Error('The actual Kafka handler did not run: ' + reports.join(','))),
          10000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
async function eventually(check: () => Promise<boolean>): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await check()) return;
    await setTimeout(50);
  }
  assert.fail('The actual Kafka state did not reach the expected condition');
}

test(
  'Latest reset skips existing records for a new group but preserves its durable resume position',
  { timeout: 30000 },
  async () => {
    const f = fixture(),
      marker = randomUUID(),
      group = 'owned-latest-' + randomUUID();
    const selected = { ...config(group), offsetReset: 'latest' as const };
    let admin: KafkaJS.Admin | undefined,
      received: KafkaRecord | undefined,
      replayed = false;
    try {
      await f.init();
      const old = await f.service.publish({ ...publication(marker), value: Buffer.from([0]) });
      admin = (f.service.native('owned') as KafkaJS.Producer<Buffer, Buffer>).dependentAdmin();
      await admin.connect();
      const first = await f.service.consume(selected, async (record) => {
        if (Buffer.from(record.key ?? []).toString() !== marker) return;
        if (record.value?.[0] === 0) replayed = true;
        else received = record;
      });
      await eventually(
        async () =>
          (await admin!.describeGroups([group], { timeout: 2000 })).groups[0]?.members.length === 1,
      );
      const publications: KafkaPublicationReceipt[] = [];
      // A bounded sequence crosses the driver's initial latest-offset fetch without a timing guess.
      for (let attempt = 0; attempt < 40 && !received; attempt++) {
        publications.push(
          await f.service.publish({ ...publication(marker), value: Buffer.from([1]) }),
        );
        await setTimeout(50);
      }
      assert.ok(received, 'A new latest group must receive a subsequently published record');
      await first.close();
      assert.equal(replayed, false);
      assert.equal(received.partition, old.partition);
      assert.ok(BigInt(received.offset) > BigInt(old.offset));
      assert.ok(publications.some((receipt) => receipt.offset === received!.offset));

      const gap = await f.service.publish({ ...publication(marker), value: Buffer.from([2]) });
      const resumed = gate<KafkaRecord>();
      const second = await f.service.consume(selected, async (record) => {
        if (Buffer.from(record.key ?? []).toString() === marker && record.value?.[0] === 2)
          resumed.resolve(record);
      });
      assert.equal((await observed(resumed.promise, f.reports)).offset, gap.offset);
      await second.close();
      assert.deepEqual(f.reports, []);
    } finally {
      await admin?.disconnect();
      await f.close();
    }
  },
);

test(
  'A detached continuation from a completed Kafka handler cannot borrow a later handler drain admission',
  { timeout: 30000 },
  async () => {
    const f = fixture(),
      marker = randomUUID(),
      group = 'owned-expired-' + randomUUID();
    const later = gate<void>(),
      entered = gate<void>(),
      release = gate<void>();
    let continuation: Promise<void> | undefined;
    try {
      await f.init();
      await f.service.consume(config(group), async (record) => {
        if (Buffer.from(record.key ?? []).toString() !== marker) return;
        if (record.value?.[0] === 1) {
          continuation = (async () => {
            await later.promise;
            await assert.rejects(f.service.publish(publication(randomUUID())), {
              code: 'EK_RESOURCE_CLOSED',
            });
          })();
          void continuation.catch(() => undefined);
        } else {
          entered.resolve();
          await release.promise;
        }
      });
      await f.service.publish({ ...publication(marker), value: Buffer.from([1]) });
      await f.service.publish({ ...publication(marker), value: Buffer.from([2]) });
      await observed(entered.promise, f.reports);
      const closing = f.close();
      later.resolve();
      await continuation;
      release.resolve();
      await closing;
      assert.deepEqual(f.reports, []);
    } finally {
      later.resolve();
      release.resolve();
      await f.close();
    }
  },
);

test(
  'Graceful Kafka shutdown drains admitted handlers and durable commits while rejecting new external work',
  { timeout: 30000 },
  async () => {
    const first = fixture(),
      second = fixture(),
      marker = randomUUID(),
      group = 'owned-drain-' + randomUUID();
    const entered = gate<void>(),
      release = gate<void>();
    let admin: KafkaJS.Admin | undefined,
      forwarded = false;
    try {
      await first.init();
      await second.init();
      admin = (second.service.native('owned') as KafkaJS.Producer<Buffer, Buffer>).dependentAdmin();
      await admin.connect();
      const receipt = await first.service.publish(publication(marker));
      await first.service.consume(config(group), async (record) => {
        if (Buffer.from(record.key ?? []).toString() !== marker) return;
        entered.resolve();
        await release.promise;
        assert.equal(
          (await first.service.publish(publication(randomUUID()))).status,
          'acknowledged',
        );
        forwarded = true;
      });
      await observed(entered.promise, first.reports);
      const closing = first.close();
      let finished = false;
      void closing.then(() => {
        finished = true;
      });
      await setTimeout(20);
      assert.equal(finished, false);
      await assert.rejects(first.service.publish(publication(randomUUID())), {
        code: 'EK_RESOURCE_CLOSED',
      });
      release.resolve();
      await closing;
      assert.equal(forwarded, true);
      const rows =
        (await admin.fetchOffsets({ groupId: group, topics: ['orders.created'], timeout: 2000 }))[0]
          ?.partitions ?? [];
      assert.ok(
        rows.some(
          (row) =>
            row.partition === receipt.partition && BigInt(row.offset) > BigInt(receipt.offset),
        ),
      );
      assert.deepEqual(first.reports, []);
    } finally {
      release.resolve();
      await admin?.disconnect();
      await first.close();
      await second.close();
    }
  },
);

test(
  'A timed-out Kafka handler cannot commit late and its physical work remains owned until it settles',
  { timeout: 30000 },
  async () => {
    const f = fixture(),
      marker = randomUUID(),
      group = 'owned-timeout-' + randomUUID();
    const entered = gate<void>(),
      release = gate<void>();
    let admin: KafkaJS.Admin | undefined;
    try {
      await f.init();
      const receipt = await f.service.publish(publication(marker));
      admin = (f.service.native('owned') as KafkaJS.Producer<Buffer, Buffer>).dependentAdmin();
      await admin.connect();
      const subscription = await f.service.consume(
        config(group),
        async (record) => {
          if (Buffer.from(record.key ?? []).toString() !== marker) return;
          entered.resolve();
          await release.promise;
        },
        { timeoutMs: 500 },
      );
      await observed(entered.promise, f.reports);
      await eventually(async () => f.reports.includes('EK_TIMEOUT'));
      await assert.rejects(subscription.close({ timeoutMs: 50 }), { code: 'EK_TIMEOUT' });
      const committed = async () => {
        const rows =
          (
            await admin!.fetchOffsets({ groupId: group, topics: ['orders.created'], timeout: 2000 })
          )[0]?.partitions ?? [];
        return rows.find((row) => row.partition === receipt.partition)?.offset ?? '-1';
      };
      assert.ok(BigInt(await committed()) <= BigInt(receipt.offset));
      release.resolve();
      await assert.rejects(subscription.close(), { code: 'EK_TIMEOUT' });
      assert.ok(BigInt(await committed()) <= BigInt(receipt.offset));
      const received = gate<void>();
      const replacement = await f.service.consume(config(group), async (record) => {
        if (Buffer.from(record.key ?? []).toString() === marker) received.resolve();
      });
      await observed(received.promise, f.reports);
      await eventually(async () => BigInt(await committed()) > BigInt(receipt.offset));
      await replacement.close();
    } finally {
      release.resolve();
      await admin?.disconnect();
      await f.close();
    }
  },
);

test(
  'Two actual Kafka group members rebalance and preserve sequential processing across member departure',
  { timeout: 30000 },
  async () => {
    const f = fixture(),
      group = 'owned-pair-' + randomUUID(),
      prefix = randomUUID();
    let admin: KafkaJS.Admin | undefined;
    const seen = new Map<string, number>(),
      inFlight = new Set<number>();
    const handler = async (record: KafkaRecord) => {
      const id = Buffer.from(record.key ?? []).toString();
      if (!id.startsWith(prefix)) return;
      assert.ok(!inFlight.has(record.partition));
      inFlight.add(record.partition);
      try {
        await assert.rejects(f.service.close(), { code: 'EK_LIFECYCLE_STATE' });
        await setTimeout(2);
        seen.set(id, (seen.get(id) ?? 0) + 1);
      } finally {
        inFlight.delete(record.partition);
      }
    };
    try {
      await f.init();
      admin = (f.service.native('owned') as KafkaJS.Producer<Buffer, Buffer>).dependentAdmin();
      await admin.connect();
      const first = await f.service.consume(config(group), handler);
      const second = await f.service.consume(config(group), handler);
      await eventually(
        async () =>
          (await admin!.describeGroups([group], { timeout: 2000 })).groups[0]?.members.length === 2,
      );
      const receipts: KafkaPublicationReceipt[] = [];
      for (let i = 0; i < 8; i++)
        receipts.push(await f.service.publish(publication(prefix + ':' + i)));
      await eventually(async () => seen.size === 8);
      await eventually(async () => {
        const rows =
          (
            await admin!.fetchOffsets({ groupId: group, topics: ['orders.created'], timeout: 2000 })
          )[0]?.partitions ?? [];
        return receipts.every((receipt) =>
          rows.some(
            (row) =>
              row.partition === receipt.partition && BigInt(row.offset) > BigInt(receipt.offset),
          ),
        );
      });
      await first.close();
      await eventually(
        async () =>
          (await admin!.describeGroups([group], { timeout: 2000 })).groups[0]?.members.length === 1,
      );
      const final = await f.service.publish(publication(prefix + ':remaining'));
      await eventually(async () => seen.has(prefix + ':remaining'));
      await eventually(async () => {
        const rows =
          (
            await admin!.fetchOffsets({ groupId: group, topics: ['orders.created'], timeout: 2000 })
          )[0]?.partitions ?? [];
        return rows.some(
          (row) => row.partition === final.partition && BigInt(row.offset) > BigInt(final.offset),
        );
      });
      await second.close();
      assert.equal(seen.size, 9);
      assert.ok([...seen.values()].every((count) => count === 1));
      assert.deepEqual(f.reports, []);
    } finally {
      await admin?.disconnect();
      await f.close();
    }
  },
);

test(
  'Managed Kafka commits only after handler success and resumes without replaying acknowledged records',
  { timeout: 30000 },
  async () => {
    const f = fixture(),
      marker = randomUUID(),
      group = 'owned-' + randomUUID();
    const entered = gate<KafkaRecord>(),
      release = gate<void>();
    let subscription: Awaited<ReturnType<typeof f.service.consume>> | undefined;
    let admin: KafkaJS.Admin | undefined;
    try {
      await f.init();
      const receipt = await f.service.publish(publication(marker));
      admin = (f.service.native('owned') as KafkaJS.Producer<Buffer, Buffer>).dependentAdmin();
      await admin.connect();
      subscription = await f.service.consume(config(group), async (record) => {
        if (Buffer.from(record.key ?? []).toString() !== marker) return;
        entered.resolve(record);
        await release.promise;
      });
      const record = await observed(entered.promise, f.reports);
      assert.equal(record.offset, receipt.offset);
      assert.deepEqual([...record.value!], [0, 128, 255]);
      assert.equal(record.verifiedTenant, undefined);
      const committed = async () => {
        const rows = await admin!.fetchOffsets({
          groupId: group,
          topics: ['orders.created'],
          timeout: 2000,
        });
        return (
          rows[0]?.partitions.find((part) => part.partition === receipt.partition)?.offset ?? '-1'
        );
      };
      assert.ok(BigInt(await committed()) <= BigInt(receipt.offset));
      release.resolve();
      await eventually(async () => BigInt(await committed()) > BigInt(receipt.offset));
      await subscription.close();
      subscription = undefined;
      let repeated = false;
      const reachedEnd = gate<void>();
      const resumed = await f.service.consume(config(group), async (next) => {
        if (Buffer.from(next.key ?? []).toString() !== marker) return;
        if (next.offset === receipt.offset) repeated = true;
        if (next.value?.length === 1 && next.value[0] === 42) reachedEnd.resolve();
      });
      await f.service.publish({ ...publication(marker), value: Buffer.from([42]) });
      await observed(reachedEnd.promise, f.reports);
      await resumed.close();
      assert.equal(repeated, false);
      assert.deepEqual(f.reports, []);
    } finally {
      release.resolve();
      await subscription?.close().catch(() => undefined);
      await admin?.disconnect();
      await f.close();
    }
  },
);

test(
  'Managed Kafka handler failure stops the member and leaves its record available for redelivery',
  { timeout: 30000 },
  async () => {
    const f = fixture(),
      marker = randomUUID(),
      group = 'owned-failure-' + randomUUID();
    const entered = gate<void>();
    try {
      await f.init();
      const receipt = await f.service.publish(publication(marker));
      const failed = await f.service.consume(config(group), async (record) => {
        if (Buffer.from(record.key ?? []).toString() !== marker) return;
        entered.resolve();
        throw new Error('Private application failure details');
      });
      await observed(entered.promise, f.reports);
      await eventually(async () => f.reports.includes('EK_KAFKA_CONSUME'));
      await assert.rejects(failed.close(), { code: 'EK_KAFKA_CONSUME' });
      assert.equal((await f.service.health('owned')).available, false);
      const redelivered = gate<KafkaRecord>();
      const replacement = await f.service.consume(config(group), async (record) => {
        if (Buffer.from(record.key ?? []).toString() === marker) redelivered.resolve(record);
      });
      assert.equal((await observed(redelivered.promise, f.reports)).offset, receipt.offset);
      await replacement.close();
      assert.ok(!JSON.stringify(f.reports).includes('Private application failure'));
    } finally {
      await f.close();
    }
  },
);
