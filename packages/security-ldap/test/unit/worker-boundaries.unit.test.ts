// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import type { WorkerInput } from '../../dist/contracts.js';

type Packet = { type: string; kind?: string; value?: unknown; entry?: unknown };
async function run(mode: string, overrides: Partial<WorkerInput> = {}): Promise<Packet[]> {
  const child = fork(new URL('../../dist/worker.js', import.meta.url), [], {
    execArgv: [
      '--experimental-test-module-mocks',
      '--import',
      new URL('../../test/fixtures/native-fault-loader.mjs', import.meta.url).href,
    ],
    env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test', ARKENIVA_LDAP_NATIVE_FAULT: mode },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    serialization: 'advanced',
  });
  const packets: Packet[] = [];
  let stderr = '';
  child.stderr?.on('data', (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  const input: WorkerInput = {
    operation: 'find',
    url: 'ldaps://127.0.0.1:9',
    startTls: false,
    bindDn: 'cn=service,dc=fixture,dc=invalid',
    bindPassword: randomBytes(24).toString('hex'),
    baseDn: 'ou=people,dc=fixture,dc=invalid',
    groupBase: 'ou=groups,dc=fixture,dc=invalid',
    template: '(uid={username})',
    allowedAttributes: ['uid', 'cn'],
    maxEntries: 3,
    maxDepth: 3,
    timeoutMs: 1000,
    username: 'owned',
    password: randomBytes(24).toString('hex'),
    userDn: 'uid=owned,ou=people,dc=fixture,dc=invalid',
    ...overrides,
  };
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  try {
    await new Promise<void>((resolve, reject) => {
      child.on('message', (packet: Packet) => {
        packets.push(packet);
        if (packet.type === 'entry' && child.connected) child.send({ type: 'ack' });
      });
      child.once('error', reject);
      child.once('close', (code) => {
        try {
          assert.equal(code, 0, stderr);
          resolve();
        } catch (error) {
          reject(error);
        }
      });
      child.send(input, (error) => {
        if (error) reject(error);
      });
    });
    assert.doesNotMatch(JSON.stringify(packets), /Private|untrusted\.invalid/);
    assert.equal(
      packets.filter((packet) => packet.type === 'error' || packet.type === 'result').length,
      1,
    );
    return packets;
  } finally {
    clearTimeout(timer);
    if (child.connected) child.kill('SIGKILL');
  }
}
function terminal(packets: Packet[]) {
  return packets.at(-1)!;
}

test('LDAP native worker sanitizes driver connection, bind and cleanup failures', async () => {
  for (const [mode, kind] of [
    ['bind-failure', 'EK_LDAP_BIND'],
    ['connect-failure', 'EK_LDAP_CONNECT'],
    ['unbound', 'EK_LDAP_BIND'],
    ['plain-twice', 'EK_LDAP_CONNECT'],
    ['secure-twice', 'EK_LDAP_CONNECT'],
  ])
    assert.deepEqual(terminal(await run(mode!)), { type: 'error', kind });
  for (const mode of ['starttls-failure', 'upgrade-without-plain', 'upgrade-twice'])
    assert.deepEqual(terminal(await run(mode, { startTls: true })), {
      type: 'error',
      kind: 'EK_LDAP_CONNECT',
    });
  assert.equal(terminal(await run('unbind-failure', { operation: 'ping' })).value, true);
});
test('LDAP native worker rejects ambiguous, malformed, unapproved and oversized projections', async () => {
  for (const mode of [
    'search-failure',
    'lost-binding',
    'missing-uid',
    'multiple-uids',
    'too-many-attributes',
    'unrequested',
    'duplicate-case',
    'too-many-values',
    'large-value',
    'bad-utf8',
    'bad-dn',
    'ambiguous',
    'page-overflow',
    'referral',
  ])
    assert.deepEqual(terminal(await run(mode)), { type: 'error', kind: 'EK_LDAP_SEARCH' }, mode);
  assert.equal(terminal(await run('empty')).value, null);
  assert.equal((terminal(await run('buffer-value')).value as { uid: string }).uid, 'owned');
  assert.equal(
    (
      terminal(
        await run('alias', {
          allowedAttributes: ['samaccountname', 'cn'],
          template: '(samaccountname={username})',
        }),
      ).value as { uid: string }
    ).uid,
    'owned',
  );
});
test('LDAP native worker acknowledges pages but never reports truncated searches as complete', async () => {
  const packets = await run('count-overflow', {
    operation: 'search',
    query: {
      baseDn: 'ou=people,dc=fixture,dc=invalid',
      filter: { template: '(uid={username})', values: { username: 'owned' } },
      attributes: ['uid', 'cn'],
      maxEntries: 1,
      pageSize: 1,
    },
  });
  assert.equal(packets.filter((packet) => packet.type === 'entry').length, 1);
  assert.deepEqual(terminal(packets), { type: 'error', kind: 'EK_LDAP_SEARCH' });
  const success = await run('normal', {
    operation: 'search',
    query: {
      baseDn: 'ou=people,dc=fixture,dc=invalid',
      filter: { template: '(uid={username})', values: { username: 'owned' } },
      attributes: ['uid', 'cn'],
      maxEntries: 2,
      pageSize: 1,
    },
  });
  assert.equal(success.filter((packet) => packet.type === 'entry').length, 1);
  assert.deepEqual(terminal(success), { type: 'result', value: null });
});
test('LDAP native worker deduplicates group cycles and fails explicit depth, count and name bounds', async () => {
  const groups = terminal(await run('group-cycle', { operation: 'groups' })).value as unknown[];
  assert.equal(groups.length, 2);
  for (const mode of ['group-missing-name', 'group-many-names', 'group-depth'])
    assert.deepEqual(terminal(await run(mode, { operation: 'groups', maxDepth: 1 })), {
      type: 'error',
      kind: 'EK_LDAP_SEARCH',
    });
  assert.deepEqual(terminal(await run('group-count', { operation: 'groups', maxEntries: 1 })), {
    type: 'error',
    kind: 'EK_LDAP_SEARCH',
  });
});
test('LDAP native worker treats only absent users and invalid user credentials as authentication failure', async () => {
  for (const mode of ['empty', 'invalid-user'])
    assert.deepEqual(terminal(await run(mode, { operation: 'verify' })), {
      type: 'result',
      value: false,
    });
  assert.deepEqual(terminal(await run('normal', { operation: 'verify' })), {
    type: 'result',
    value: true,
  });
  assert.deepEqual(terminal(await run('bind-failure', { operation: 'verify' })), {
    type: 'error',
    kind: 'EK_LDAP_BIND',
  });
});
