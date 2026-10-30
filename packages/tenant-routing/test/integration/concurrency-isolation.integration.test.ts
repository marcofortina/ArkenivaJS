// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { setImmediate as nextTurn, setTimeout as delay } from 'node:timers/promises';
import { within } from '@arkenivajs/core/support';
import type { RouteContext } from '@arkenivajs/core';
import { registryContentChecksum } from '../../dist/registry.js';
import { fixture, registry, send, settings } from '../http-fixture.js';

test(
  'Independent application instances retain separate operation permits while tenants share each local limit',
  { timeout: 15000 },
  async () => {
    const snapshot = registry();
    for (const operation of snapshot.operations) {
      operation.maxConcurrency = 1;
      operation.timeoutMs = 5000;
    }
    snapshot.contentChecksum = registryContentChecksum(snapshot);
    const base = settings(snapshot);
    let enter!: () => void,
      release!: () => void,
      heldFinished = false;
    const entered = new Promise<void>((resolve) => {
        enter = resolve;
      }),
      gate = new Promise<void>((resolve) => {
        release = resolve;
      });

    const effects = new Map<string, { tenant: string; operation: string; id: string }[]>([
      ['first', []],
      ['second', []],
    ]);
    const input = (instance: string) => ({
      ...base,
      handlers: Object.fromEntries(
        Object.entries(base.handlers).map(([name, handler]) => [
          name,
          async (context: RouteContext) => {
            const id = context.params.id ?? (context.body as { id: string }).id,
              operation = context.params.id === undefined ? 'orders.create' : 'orders.read';
            effects.get(instance)!.push({ tenant: context.auth!.tenantId, operation, id });
            if (instance === 'first' && id === 'held') {
              enter();
              await gate;
            }
            return handler(context);
          },
        ]),
      ),
    });
    const first = await fixture(input('first'));
    let second: Awaited<ReturnType<typeof fixture>> | undefined,
      held: ReturnType<typeof send> | undefined;
    try {
      second = await fixture(input('second'));
      const firstAuthorization = await first.token('north'),
        secondAuthorization = await second.token('north');
      held = send(first.origin, '/api/orders/held', {
        headers: { authorization: firstAuthorization },
      });
      void held.then(
        () => {
          heldFinished = true;
        },
        () => {},
      );
      await within(() => entered, { timeoutMs: 2000 });
      for (const tenant of ['north', 'south']) {
        const saturated = await send(first.origin, '/api/orders/blocked', {
          headers: { authorization: await first.token(tenant) },
        });
        assert.equal(saturated.status, 503, saturated.body);
        assert.equal((saturated.json().error as { code: string }).code, 'EK_TROUTE_CAPACITY');
      }
      assert.equal(heldFinished, false);
      assert.equal(effects.get('first')!.length, 1);
      const independent = await send(second.origin, '/api/orders/independent', {
        headers: { authorization: secondAuthorization },
      });
      assert.equal(independent.status, 200, independent.body);
      assert.deepEqual(independent.json(), {
        tenant: 'north',
        implementation: 'north',
        id: 'independent',
      });
      const otherOperation = await send(first.origin, '/api/orders', {
        method: 'POST',
        body: { id: 'created' },
        headers: { authorization: firstAuthorization },
      });
      assert.equal(otherOperation.status, 200, otherOperation.body);
      assert.deepEqual(otherOperation.json(), {
        tenant: 'north',
        implementation: 'north',
        id: 'created',
      });
      assert.equal(heldFinished, false);
      release();
      const completed = await held;
      assert.equal(completed.status, 200, completed.body);
      assert.deepEqual(completed.json(), { tenant: 'north', implementation: 'north', id: 'held' });
      await nextTurn();
      const recovered = await send(first.origin, '/api/orders/recovered', {
        headers: { authorization: firstAuthorization },
      });
      assert.equal(recovered.status, 200, recovered.body);
      await nextTurn();
      assert.deepEqual(effects.get('first'), [
        { tenant: 'north', operation: 'orders.read', id: 'held' },
        { tenant: 'north', operation: 'orders.create', id: 'created' },
        { tenant: 'north', operation: 'orders.read', id: 'recovered' },
      ]);
      assert.deepEqual(effects.get('second'), [
        { tenant: 'north', operation: 'orders.read', id: 'independent' },
      ]);
      for (const owner of [first, second]) {
        assert.equal(owner.service.api.revision(), snapshot.revision);
        const resolution = owner.service.api.resolve('orders.read', await owner.tenant('north'));
        assert.equal(resolution?.revision, snapshot.revision);
        assert.equal(resolution?.activationGeneration, snapshot.activationGeneration);
      }
      assert.doesNotMatch(first.logs() + second.logs(), /Bearer /);
    } finally {
      release();
      await held?.catch(() => undefined);
      const closed = await Promise.allSettled([first.close(), second?.close()]);
      for (const result of closed) assert.equal(result.status, 'fulfilled');
      assert.equal(first.app.state, 'CLOSED');
      if (second) assert.equal(second.app.state, 'CLOSED');
    }
  },
);

test(
  'Independent Node processes enforce local operation limits without inventing a fleet-wide quota',
  { timeout: 15000 },
  async (t) => {
    const snapshot = registry();
    for (const operation of snapshot.operations) {
      operation.maxConcurrency = 1;
      operation.timeoutMs = 5000;
    }
    snapshot.contentChecksum = registryContentChecksum(snapshot);
    interface Message {
      kind: string;
      id?: number;
      origin?: string;
      north?: string;
      south?: string;
      pid?: number;
      state?: string;
      effects?: { tenant: string; operation: string; id: string }[];
      resolution?: { revision: string; activationGeneration: number };
    }
    const start = async (instance: string) => {
      const child = fork(new URL('../concurrency-worker.js', import.meta.url), [], {
        execArgv: ['--max-old-space-size=128'],
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      });
      const exited = once(child, 'exit'),
        messages: Message[] = [];
      child.on('message', (message: Message) => {
        messages.push(message);
        assert.ok(messages.length <= 32);
      });
      t.after(async () => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        await exited;
      });
      const until = async (predicate: (message: Message) => boolean) => {
        const deadline = performance.now() + 5000;
        for (;;) {
          const value = messages.find(predicate);
          if (value) return value;
          assert.equal(child.exitCode, null, 'The owned concurrency worker exited prematurely');
          assert.equal(child.signalCode, null, 'The owned concurrency worker was terminated');
          assert.ok(
            performance.now() < deadline,
            'The bounded concurrency fixture exceeded its IPC deadline',
          );
          await delay(5);
        }
      };
      let sequence = 0;
      const command = async (kind: string) => {
        const id = ++sequence;
        child.send({ kind, id });
        return until((message) => message.kind === 'reply' && message.id === id);
      };
      child.send({ kind: 'start', instance, snapshot });
      const ready = await until((message) => message.kind === 'ready');
      assert.equal(typeof ready.origin, 'string');
      assert.equal(new URL(ready.origin!).hostname, '127.0.0.1');
      assert.equal(typeof ready.north, 'string');
      assert.equal(typeof ready.south, 'string');
      assert.equal(ready.pid, child.pid);
      assert.notEqual(ready.pid, process.pid);
      return { ready, until, command, exited };
    };
    const first = await start('first'),
      second = await start('second');
    assert.notEqual(first.ready.pid, second.ready.pid);
    let heldFinished = false;
    const held = send(first.ready.origin!, '/api/orders/held', {
      headers: { authorization: first.ready.north! },
    });
    void held.then(
      () => {
        heldFinished = true;
      },
      () => {},
    );
    try {
      await first.until((message) => message.kind === 'entered');
      for (const authorization of [first.ready.north!, first.ready.south!]) {
        const blocked = await send(first.ready.origin!, '/api/orders/blocked', {
          headers: { authorization },
        });
        assert.equal(blocked.status, 503, blocked.body);
        assert.equal((blocked.json().error as { code: string }).code, 'EK_TROUTE_CAPACITY');
      }
      const independent = await send(second.ready.origin!, '/api/orders/independent', {
        headers: { authorization: second.ready.north! },
      });
      assert.equal(independent.status, 200, independent.body);
      assert.deepEqual(independent.json(), {
        tenant: 'north',
        implementation: 'north',
        id: 'independent',
      });
      const otherOperation = await send(first.ready.origin!, '/api/orders', {
        method: 'POST',
        body: { id: 'created' },
        headers: { authorization: first.ready.north! },
      });
      assert.equal(otherOperation.status, 200, otherOperation.body);
      assert.deepEqual(otherOperation.json(), {
        tenant: 'north',
        implementation: 'north',
        id: 'created',
      });
      assert.equal(heldFinished, false);
      await first.command('release');
      assert.equal((await held).status, 200);
      const recovered = await send(first.ready.origin!, '/api/orders/recovered', {
        headers: { authorization: first.ready.north! },
      });
      assert.equal(recovered.status, 200, recovered.body);
      const a = await first.command('snapshot'),
        b = await second.command('snapshot');
      assert.deepEqual(a.effects, [
        { tenant: 'north', operation: 'orders.read', id: 'held' },
        { tenant: 'north', operation: 'orders.create', id: 'created' },
        { tenant: 'north', operation: 'orders.read', id: 'recovered' },
      ]);
      assert.deepEqual(b.effects, [
        { tenant: 'north', operation: 'orders.read', id: 'independent' },
      ]);
      for (const response of [a, b]) {
        assert.equal(response.resolution?.revision, snapshot.revision);
        assert.equal(response.resolution?.activationGeneration, snapshot.activationGeneration);
        assert.equal(response.state, 'READY');
      }
    } finally {
      await first.command('release');
      await held.catch(() => undefined);
      const stopped = await Promise.all([first.command('stop'), second.command('stop')]);
      assert.ok(stopped.every((value) => value.state === 'CLOSED'));
      const exits = await Promise.all([first.exited, second.exited]);
      assert.deepEqual(exits, [
        [0, null],
        [0, null],
      ]);
    }
  },
);
