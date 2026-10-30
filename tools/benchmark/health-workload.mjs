// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { request } from 'node:http';

function origin(fixture) {
  const value = new URL(fixture.origin);
  assert.equal(value.protocol, 'http:');
  assert.equal(value.hostname, '127.0.0.1');
  assert.equal(value.origin, fixture.origin);
  assert.ok(value.port.length > 0);
  assert.equal(typeof fixture.marker, 'string');
  assert.ok(fixture.marker.length > 0 && fixture.marker.length <= 64);
  return value.origin;
}

function exchange(fixture, ready, signal) {
  const control = ready !== undefined;
  return new Promise((resolve, reject) => {
    const outgoing = request(
      origin(fixture) + (control ? '/control' : '/probe'),
      {
        method: control ? 'POST' : 'GET',
        agent: false,
        signal: signal ?? AbortSignal.timeout(1000),
        headers: {
          'x-health-fixture': fixture.marker,
          ...(control ? { 'content-type': 'application/json' } : {}),
        },
      },
      (response) => {
        let body = '';
        response.on('data', (chunk) => {
          body += chunk.toString('utf8');
          if (Buffer.byteLength(body) > 128)
            response.destroy(new Error('The owned health response exceeds its budget'));
        });
        response.once('error', reject);
        response.once('end', () => {
          try {
            if (control) assert.equal(response.statusCode, 204);
            else assert.equal(body, fixture.marker);
            resolve(response.statusCode === (control ? 204 : 200));
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    outgoing.once('error', reject);
    outgoing.end(control ? JSON.stringify({ ready }) : undefined);
  });
}

export function healthSettings(fixture) {
  origin(fixture);
  return {
    timeoutMs: 1000,
    checks: [
      {
        name: 'dependency',
        check: (_context, options) => exchange(fixture, undefined, options.signal),
      },
    ],
  };
}

/** The baseline invokes the same actual HTTP probe, without registry lifecycle or coalescing. */
export function nativeHealth(fixture) {
  origin(fixture);
  let closed = false;
  return {
    live: () => ({ status: 'live' }),
    async ready() {
      assert.equal(closed, false);
      const confirmed = await exchange(fixture);
      return Object.freeze({
        status: confirmed ? 'ready' : 'not_ready',
        failing: Object.freeze(confirmed ? [] : ['dependency']),
      });
    },
    close() {
      closed = true;
    },
  };
}

export async function verifyHealth(service, fixture) {
  for (let index = 0; index < 8; index++) {
    assert.deepEqual(await service.ready(), { status: 'ready', failing: [] });
  }
  try {
    await exchange(fixture, false);
    const failed = await service.ready();
    assert.equal(failed.status, 'not_ready');
    assert.deepEqual(failed.failing, ['dependency']);
    assert.deepEqual(await service.live(), { status: 'live' });
  } finally {
    await exchange(fixture, true);
  }
  return {
    readySnapshots: 8,
    failedSnapshots: 1,
    nativeProbeObserved: true,
    livenessIndependent: true,
  };
}

export function healthWorkload(service) {
  return { ready: () => service.ready() };
}
