// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';

/** Bounds include the existing fixed-rate one-hour soak; no complete log objects are retained. */
export const HTTP_LOG_AUDIT_LIMITS = Object.freeze({
  maxBytes: 1_073_741_824,
  maxRows: 2_000_000,
  maxLineBytes: 65_536,
});

const auditMessage = 'Authentication completed';
const completedMessage = 'HTTP request completed';
const rejectedCodes = new Set([
  'EK_AUTH_REQUIRED',
  'EK_AUTH_INVALID',
  'EK_ABORTED',
  'EK_TIMEOUT',
  'EK_RESOURCE_CLOSED',
  'EK_MFA_POLICY',
]);
const allowedAuditKeys = new Set([
  'level',
  'time',
  'service',
  'serviceVersion',
  'environment',
  'msg',
  'requestId',
  'traceId',
  'outcome',
  'code',
]);

/** A queued empty write acknowledges all earlier stream writes without adding a log row. */
export async function logWriteBoundary(stream) {
  await new Promise((resolve, reject) => {
    stream.write('', (error) => (error ? reject(error) : resolve()));
  });
  assert.equal(stream.writableLength, 0, 'Benchmark log writes remain pending');
  assert.ok(Number.isSafeInteger(stream.bytesWritten) && stream.bytesWritten >= 0);
  return stream.bytesWritten;
}

/** Read exact acknowledged file bytes outside the timed CPU and profiler windows. */
export async function auditLogWindow(path, start, end) {
  assert.ok(Number.isSafeInteger(start) && Number.isSafeInteger(end) && start >= 0 && end >= start);
  assert.ok(
    end - start <= HTTP_LOG_AUDIT_LIMITS.maxBytes,
    'The benchmark log audit exceeds its byte bound',
  );
  const http = new Map(),
    audit = new Map();
  const result = {
    startByte: start,
    endByte: end,
    bytes: end - start,
    rows: 0,
    httpCompleted: 0,
    authenticationVerified: 0,
    authenticationRejected: 0,
    protectedSuccesses: 0,
    otherRows: 0,
    authenticationAuditBytes: 0,
  };
  if (end === start) return result;
  let pending = '',
    observedBytes = 0;
  const stream = createReadStream(path, { start, end: end - 1, encoding: 'utf8' });
  try {
    for await (const chunk of stream) {
      observedBytes += Buffer.byteLength(chunk);
      pending += chunk;
      let newline;
      while ((newline = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        assert.ok(
          Buffer.byteLength(line) <= HTTP_LOG_AUDIT_LIMITS.maxLineBytes &&
            ++result.rows <= HTTP_LOG_AUDIT_LIMITS.maxRows,
        );
        let row;
        try {
          row = JSON.parse(line);
        } catch {
          throw new Error('The benchmark log audit is invalid');
        }
        assert.ok(row && typeof row === 'object' && !Array.isArray(row));
        if (row.msg === completedMessage) {
          assert.equal(row.level, 30);
          assert.ok(typeof row.requestId === 'string' && !http.has(row.requestId));
          assert.ok(['/json', '/authenticated', '/database'].includes(row.route));
          assert.ok(Number.isInteger(row.status) && row.status >= 100 && row.status <= 599);
          http.set(row.requestId, row.route === '/json');
          result.httpCompleted++;
          if (row.route !== '/json' && row.status < 400) result.protectedSuccesses++;
        } else if (row.msg === auditMessage) {
          assert.equal(row.level, 30);
          assert.ok(typeof row.requestId === 'string' && !audit.has(row.requestId));
          assert.ok(
            Object.keys(row).every((key) => allowedAuditKeys.has(key)),
            'Unexpected authentication log fields',
          );
          assert.ok(row.outcome === 'verified' || row.outcome === 'rejected');
          if (row.outcome === 'verified') {
            assert.equal(row.code, undefined);
            result.authenticationVerified++;
          } else {
            assert.ok(rejectedCodes.has(row.code), 'Unexpected authentication rejection code');
            result.authenticationRejected++;
          }
          audit.set(row.requestId, row.outcome);
          result.authenticationAuditBytes += Buffer.byteLength(line) + 1;
        } else result.otherRows++;
      }
      assert.ok(Buffer.byteLength(pending) <= HTTP_LOG_AUDIT_LIMITS.maxLineBytes);
    }
    assert.equal(pending, '', 'The benchmark log window contains an incomplete row');
    assert.equal(observedBytes, end - start, 'The benchmark log window is incomplete');
    for (const [requestId, isPublic] of http) {
      if (isPublic) assert.equal(audit.has(requestId), false);
      else assert.ok(audit.has(requestId), 'An authenticated request is missing its audit');
    }
    for (const requestId of audit.keys())
      assert.ok(http.has(requestId), 'An audit has no completed request');
    return result;
  } finally {
    stream.destroy();
  }
}
