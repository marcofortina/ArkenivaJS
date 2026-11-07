// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createWriteStream } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { logWriteBoundary, auditLogWindow, HTTP_LOG_AUDIT_LIMITS } from '../http-log-audit.mjs';
import { httpBenchmarkPolicy } from '../http-policy.mjs';

const auth = (requestId, outcome, code) => ({
  level: 30,
  msg: 'Authentication completed',
  requestId,
  outcome,
  ...(code ? { code } : {}),
});
const completed = (requestId, route, status) => ({
  level: 30,
  msg: 'HTTP request completed',
  requestId,
  route,
  status,
});
const encode = (rows) => rows.map((row) => JSON.stringify(row) + '\n').join('');

test('Actual acknowledged log byte windows exclude warmup and correlate verified, denied and public requests', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-http-log-audit-'));
  const path = join(directory, 'application.jsonl');
  const sink = createWriteStream(path, { flags: 'wx', mode: 0o600 });
  try {
    const warmup = encode([auth('warmup', 'verified'), completed('warmup', '/authenticated', 200)]);
    sink.write(warmup);
    const start = await logWriteBoundary(sink);
    assert.equal(start, Buffer.byteLength(warmup));
    const measured = encode([
      auth('good', 'verified'),
      completed('good', '/authenticated', 200),
      auth('scope-denied', 'verified'),
      completed('scope-denied', '/database', 403),
      auth('invalid', 'rejected', 'EK_AUTH_INVALID'),
      completed('invalid', '/database', 401),
      completed('public', '/json', 200),
    ]);
    sink.write(measured);
    const end = await logWriteBoundary(sink);
    const result = await auditLogWindow(path, start, end);
    assert.equal(result.bytes, Buffer.byteLength(measured));
    assert.equal(result.rows, 7);
    assert.equal(result.httpCompleted, 4);
    assert.equal(result.authenticationVerified, 2);
    assert.equal(result.authenticationRejected, 1);
    assert.equal(result.protectedSuccesses, 1);
    assert.equal(result.otherRows, 0);
    assert.equal(
      result.authenticationAuditBytes,
      Buffer.byteLength(
        encode([
          auth('good', 'verified'),
          auth('scope-denied', 'verified'),
          auth('invalid', 'rejected', 'EK_AUTH_INVALID'),
        ]),
      ),
    );
  } finally {
    await new Promise((resolve, reject) => {
      sink.once('error', reject);
      sink.end(resolve);
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test('Log audits reject missing, duplicate, uncorrelated, non-INFO or sensitive authentication rows', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-http-log-refusal-'));
  try {
    const cases = [
      [completed('missing', '/database', 200)],
      [auth('orphan', 'verified')],
      [
        auth('duplicate', 'verified'),
        auth('duplicate', 'verified'),
        completed('duplicate', '/authenticated', 200),
      ],
      [auth('public', 'verified'), completed('public', '/json', 200)],
      [
        { ...auth('secret', 'verified'), authorization: 'inert-fixture' },
        completed('secret', '/authenticated', 200),
      ],
      [{ ...auth('warning', 'verified'), level: 40 }, completed('warning', '/authenticated', 200)],
      [auth('invalid-code', 'rejected', 'EK_FORGED'), completed('invalid-code', '/database', 401)],
    ];
    for (const [index, rows] of cases.entries()) {
      const path = join(directory, 'case-' + index + '.jsonl');
      const value = encode(rows);
      await writeFile(path, value);
      await assert.rejects(auditLogWindow(path, 0, Buffer.byteLength(value)));
    }
    const partial = join(directory, 'partial.jsonl');
    await writeFile(partial, JSON.stringify(completed('public', '/json', 200)));
    await assert.rejects(
      auditLogWindow(
        partial,
        0,
        Buffer.byteLength(JSON.stringify(completed('public', '/json', 200))),
      ),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Log audit bounds retain the original fixed-rate one-hour soak capacity', async () => {
  const soak = httpBenchmarkPolicy('soak');
  const requestsPerRoute = soak.measuredSeconds * 50 + 1;
  const completionAndAuthenticationRows = requestsPerRoute * (3 + 2);
  assert.ok(completionAndAuthenticationRows > 900000);
  assert.ok(HTTP_LOG_AUDIT_LIMITS.maxRows >= completionAndAuthenticationRows);
  // The controlled HTTP fixture emits short fixed-field rows; this is not a general log size guarantee.
  assert.ok(HTTP_LOG_AUDIT_LIMITS.maxBytes >= completionAndAuthenticationRows * 512);
  await assert.rejects(auditLogWindow('/unread-boundary', 0, HTTP_LOG_AUDIT_LIMITS.maxBytes + 1));
});
