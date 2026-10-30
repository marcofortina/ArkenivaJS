// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import type { TestContext } from 'node:test';
import childProcess from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { setImmediate } from 'node:timers/promises';
import { randomBytes } from 'node:crypto';
import { createLdapService } from '../../dist/index.js';
import type { LdapSettings } from '../../dist/index.js';

type Action = (peer: Peer, input: unknown, done: (error: Error | null) => void) => void;
/** Model only local child-process failure events; native directory compatibility has separate real tests. */
class Peer extends EventEmitter {
  connected = true;
  closed = false;
  kills = 0;
  constructor(readonly action: Action) {
    super();
  }
  send(input: unknown, done: (error: Error | null) => void) {
    this.action(this, input, done);
    return true;
  }
  finish(code: number | null = 0) {
    if (this.closed) return;
    this.closed = true;
    this.connected = false;
    this.emit('close', code);
  }
  kill() {
    this.kills++;
    queueMicrotask(() => this.finish(null));
    return true;
  }
}
function transport(t: TestContext) {
  let action: Action | null = null;
  const peers: Peer[] = [];
  t.mock.method(childProcess, 'fork', ((
    _path: unknown,
    _args: unknown,
    options: childProcess.ForkOptions,
  ) => {
    assert.equal(options.env?.NODE_DEBUG, undefined);
    if (!action) throw new Error('Private process creation failure');
    const peer = new Peer(action);
    peers.push(peer);
    return peer as unknown as ChildProcess;
  }) as typeof childProcess.fork);
  syncBuiltinESMExports();
  t.after(() => {
    t.mock.restoreAll();
    syncBuiltinESMExports();
  });
  return {
    peers,
    set(value: Action | null) {
      action = value;
    },
  };
}
function settings(): LdapSettings {
  const credential = randomBytes(24).toString('base64url');
  return {
    url: 'ldaps://127.0.0.1:9',
    baseDn: 'ou=people,dc=fixture,dc=invalid',
    groupSearchBaseDn: 'ou=groups,dc=fixture,dc=invalid',
    userFilterTemplate: '(uid={username})',
    serviceBindDnRef: 'owned://dn',
    serviceBindPasswordRef: 'owned://credential',
    environment: 'test',
    timeoutMs: 1000,
    secretProvider: {
      async get(reference) {
        return {
          bytes: Buffer.from(
            reference === 'owned://dn' ? 'cn=service,dc=fixture,dc=invalid' : credential,
          ),
          keyVersion: 'one',
        };
      },
    },
  };
}
const success: Action = (peer, _input, done) =>
  queueMicrotask(() => {
    done(null);
    peer.emit('message', { type: 'result', value: true });
    peer.finish();
  });
test('LDAP process creation, send, error and premature close failures never expose private diagnostics or retain admission', async (t) => {
  const wire = transport(t),
    directory = createLdapService(settings());
  const failures: (Action | null)[] = [
    null,
    () => {
      throw new Error('Private send failure');
    },
    (_peer, _input, done) => done(new Error('Private IPC failure')),
    (peer) => queueMicrotask(() => peer.emit('error', new Error('Private process error'))),
    (peer) => queueMicrotask(() => peer.finish(1)),
    (peer) => queueMicrotask(() => peer.finish(0)),
  ];
  for (const failure of failures) {
    wire.set(failure);
    await assert.rejects(directory.ping(), (error) => {
      assert.equal((error as { code: string }).code, 'EK_LDAP_CONNECT');
      assert.equal(JSON.stringify(error).includes('Private'), false);
      return true;
    });
    await setImmediate();
    wire.set(success);
    assert.equal(await directory.ping(), true);
  }
  assert.ok(wire.peers.every((peer) => peer.closed));
});
test('LDAP malformed IPC and unknown native error classes never acknowledge a directory result', async (t) => {
  const wire = transport(t),
    directory = createLdapService(settings());
  for (const message of [
    null,
    { type: 'unknown' },
    { type: 'error', kind: 'Private native diagnostic' },
    { type: 'measure', name: 'bind', value: NaN },
    { type: 'measure', name: 'bind', value: -1 },
    { type: 'measure', name: 'bind', value: 30001 },
    { type: 'measure', name: 'unknown', value: 1 },
    { type: 'entry', entry: {} },
    { type: 'result', value: true, extra: 'private' },
  ]) {
    wire.set((peer) => queueMicrotask(() => peer.emit('message', message)));
    await assert.rejects(directory.ping(), { code: 'EK_LDAP_SEARCH' });
    await setImmediate();
  }
  for (const kind of ['EK_LDAP_BIND', 'EK_LDAP_SEARCH', 'EK_LDAP_FILTER', 'EK_LDAP_CONNECT']) {
    wire.set((peer) =>
      queueMicrotask(() => {
        peer.emit('message', { type: 'binding' });
        peer.emit('message', { type: 'error', kind });
      }),
    );
    await assert.rejects(directory.ping(), (error) => {
      assert.equal((error as { code: string }).code, kind);
      assert.equal((error as { details: { outcome: string } }).details.outcome, 'unknown');
      return true;
    });
    await setImmediate();
  }
  wire.set(success);
  assert.equal(await directory.ping(), true);
});

test('LDAP results require successful native process exit and duplicate or late results cannot replace failure', async (t) => {
  const wire = transport(t),
    directory = createLdapService(settings());
  wire.set((peer) => queueMicrotask(() => peer.emit('message', { type: 'result', value: true })));
  let acknowledged = false;
  const pending = directory.ping().then((value) => {
    acknowledged = true;
    return value;
  });
  await setImmediate();
  assert.equal(acknowledged, false);
  wire.peers.at(-1)!.finish();
  assert.equal(await pending, true);
  for (const action of [
    (peer: Peer) => {
      peer.emit('message', { type: 'result', value: true });
      peer.finish(1);
    },
    (peer: Peer) => {
      peer.emit('message', { type: 'result', value: true });
      peer.emit('message', { type: 'result', value: true });
    },
    (peer: Peer) => {
      peer.emit('message', { type: 'error', kind: 'EK_LDAP_BIND' });
      peer.emit('message', { type: 'result', value: true });
    },
  ]) {
    wire.set((peer) => queueMicrotask(() => action(peer)));
    await assert.rejects(directory.ping());
    await setImmediate();
  }
  wire.set(success);
  assert.equal(await directory.ping(), true);
});

test('LDAP search acknowledgement failure closes the process and cannot yield another page', async (t) => {
  const wire = transport(t),
    directory = createLdapService(settings());
  wire.set((peer, input, done) => {
    if ((input as { type?: string }).type === 'ack') {
      done(new Error('Private acknowledgement failure'));
      return;
    }
    queueMicrotask(() => {
      done(null);
      peer.emit('message', {
        type: 'entry',
        entry: { dn: 'cn=owned,dc=fixture,dc=invalid', attributes: { cn: ['owned'] } },
      });
    });
  });
  const rows = directory.search({
      baseDn: 'ou=people,dc=fixture,dc=invalid',
      filter: { template: '(uid={username})', values: { username: 'owned' } },
      attributes: ['cn'],
    }),
    iterator = rows[Symbol.asyncIterator]();
  const first = await iterator.next();
  assert.equal(first.done, false);
  assert.ok(Object.isFrozen(first.value));
  assert.ok(Object.isFrozen(first.value?.attributes.cn));
  await assert.rejects(iterator.next(), { code: 'EK_LDAP_CONNECT' });
  await iterator.return?.();
  await setImmediate();
  assert.ok(wire.peers.every((peer) => peer.closed));
  wire.set(success);
  assert.equal(await directory.ping(), true);
});

test('LDAP operation cleanup never consults cancellation hooks replaced after native capture', async (t) => {
  const wire = transport(t);
  wire.set(success);
  const directory = createLdapService(settings()),
    controller = new AbortController(),
    original = controller.signal.removeEventListener;
  let effects = 0;
  const pending = directory.ping({ signal: controller.signal });
  Object.defineProperty(controller.signal, 'removeEventListener', {
    value(...args: Parameters<typeof original>) {
      effects++;
      return Reflect.apply(original, controller.signal, args);
    },
  });
  assert.equal(await pending, true);
  assert.equal(effects, 0);
});
