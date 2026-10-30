// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Bench } from 'tinybench';
import { setImmediate as nextTurn } from 'node:timers/promises';
import {
  magiclinkPorts,
  verifyMagiclink,
  magiclinkWorkload,
  completeMagiclink,
  magiclinkIterations,
  magiclinkWarmupIterations,
} from '../magiclink-workload.mjs';

test('Magic-link comparison rejects foreign provider endpoints and request authority overrides before I/O', () => {
  for (const endpoint of [
    'http://foreign.invalid:1/provider',
    'https://127.0.0.1:1/provider',
    'http://user:pass@127.0.0.1:1/provider',
    'http://127.0.0.1:1/provider?override=true',
    'http://127.0.0.1:1/foreign',
  ])
    assert.throws(() => magiclinkPorts({ endpoint, bearer: 'owned-test-only' }));
});

function unitFixture() {
  const fixture = {
      endpoint: 'http://127.0.0.1:1/provider',
      bearer: 'unit-only',
      sampleIssues: true,
    },
    original = globalThis.fetch,
    consumed = new Set();
  let issued = 0,
    transform = (value) => value;
  const subject = {
    issuer: 'https://unit.invalid',
    subject: 'unit-owner',
    tenantId: 'unit-tenant',
  };
  globalThis.fetch = async (url, request) => {
    assert.equal(String(url), fixture.endpoint);
    assert.equal(request.headers.authorization, 'Bearer ' + fixture.bearer);
    const { method, args } = JSON.parse(request.body);
    let result;
    if (method === 'grant') result = { token: 'unit-initial', issueId: 'unit-profile' };
    else {
      assert.equal(method, 'sampleIssue');
      assert.deepEqual(args, ['unit-profile']);
      issued++;
      result = { token: 'unit-sample-' + issued, issueId: 'unit-id-' + issued, subject };
    }
    return new globalThis.Response(JSON.stringify({ result }), { status: 200 });
  };
  const service = {
    async consume(token, context) {
      assert.equal(context.method, 'POST');
      assert.equal(context.purpose, 'login');
      assert.equal(consumed.has(token), false);
      consumed.add(token);
      const result = {
        intent: 'login',
        subject: {
          issuer: subject.issuer,
          subject: subject.subject,
          tenant: { tenantId: subject.tenantId },
        },
        verifiedAt: new Date().toISOString(),
      };
      return token === 'unit-initial' ? result : transform(result);
    },
  };
  return {
    fixture,
    service,
    restore: () => {
      globalThis.fetch = original;
    },
    issued: () => issued,
    transform: (value) => {
      transform = value;
    },
  };
}

test('Magic-link smoke retains actual Tinybench issue/consume callbacks and refuses extra issuance after the bounded corpus', async () => {
  const testCase = unitFixture();
  try {
    await verifyMagiclink(testCase.service, testCase.fixture);
    const callback = magiclinkWorkload(testCase.service).issueAndConsume;
    const bench = new Bench({
      iterations: magiclinkIterations,
      time: 0,
      warmup: true,
      warmupIterations: magiclinkWarmupIterations,
      warmupTime: 0,
      retainSamples: true,
    });
    bench.add('issueAndConsume', callback, { async: true });
    await bench.run();
    const values = bench.tasks[0].result.latency.samples;
    assert.equal(values.length, 100);
    assert.equal(testCase.issued(), 120);
    await assert.rejects(callback());
    assert.equal(testCase.issued(), 120);
    const result = completeMagiclink(testCase.service, {
      measure: true,
      records: [
        {
          operation: 'issueAndConsume',
          sampleCount: 100,
          warmupIterations: 20,
          rawLatency: { unit: 'milliseconds', values },
        },
      ],
    });
    assert.equal(result.checkedConsumptions, 120);
    assert.equal(result.uniqueIssueIds, true);
    assert.equal(result.peakRetainedResults, 120);
    assert.equal(result.maximumRetainedResults, 128);
    assert.doesNotMatch(JSON.stringify(result), /unit-owner|unit-id|unit-sample/);
    await assert.rejects(callback());
  } finally {
    testCase.restore();
  }
});

test('Magic-link completion refuses a successful-looking corpus with changed owner, tenant or intent', async () => {
  for (const transform of [
    (value) => ({ ...value, intent: 'email-verify' }),
    (value) => ({ ...value, subject: { ...value.subject, subject: 'foreign' } }),
    (value) => ({ ...value, subject: { ...value.subject, tenant: { tenantId: 'foreign' } } }),
  ]) {
    const testCase = unitFixture();
    try {
      await verifyMagiclink(testCase.service, testCase.fixture);
      testCase.transform(transform);
      const callback = magiclinkWorkload(testCase.service).issueAndConsume;
      for (let index = 0; index < 120; index++) await callback();
      assert.throws(() =>
        completeMagiclink(testCase.service, {
          measure: true,
          records: [
            {
              operation: 'issueAndConsume',
              sampleCount: 100,
              warmupIterations: 20,
              rawLatency: { unit: 'milliseconds', values: Array(100).fill(1) },
            },
          ],
        }),
      );
      await assert.rejects(callback());
    } finally {
      testCase.restore();
    }
  }
});

test('Magic-link sampling awaits physical consumption and cannot queue or issue another token behind it', async () => {
  const testCase = unitFixture();
  let release, entered;
  const held = new Promise((done) => {
      release = done;
    }),
    started = new Promise((done) => {
      entered = done;
    });
  try {
    await verifyMagiclink(testCase.service, testCase.fixture);
    testCase.transform(async (value) => {
      entered();
      await held;
      return value;
    });
    const callback = magiclinkWorkload(testCase.service).issueAndConsume;
    let settled = false;
    const pending = callback().finally(() => {
      settled = true;
    });
    await started;
    await nextTurn();
    assert.equal(settled, false);
    await assert.rejects(callback());
    assert.equal(testCase.issued(), 1);
    release();
    await pending;
    assert.throws(() => completeMagiclink(testCase.service, { measure: false, records: [] }));
    await assert.rejects(callback());
  } finally {
    release();
    testCase.restore();
  }
});
