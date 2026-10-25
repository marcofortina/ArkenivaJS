// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { BSON } from 'mongodb';
import { customerDTO, runMongoDBExample } from '../../dist/main.js';

test('The MongoDB consumer explicitly converts native BSON identity, decimal and int64 to exact JSON DTO fields', () => {
  const row = {
    _id: new BSON.ObjectId(),
    tenantId: 'trusted-tenant',
    name: 'Ada',
    balance: BSON.Decimal128.fromString('1234567890.123456789'),
    exact: BSON.Long.fromString('9007199254740993'),
  };
  const dto = customerDTO(row);
  assert.deepEqual(JSON.parse(JSON.stringify(dto)), {
    id: row._id.toHexString(),
    name: 'Ada',
    balance: '1234567890.123456789',
    exact: '9007199254740993',
  });
  assert.equal(Object.isFrozen(dto), true);
  assert.throws(() => customerDTO({ ...row, exact: 9007199254740992 } as never), {
    code: 'EK_CONFIG_INVALID',
  });
});

test('The MongoDB consumer requires explicit live authorization and prints safe CLI errors', async () => {
  const disposable = process.env.ARKENIVA_MONGODB_DISPOSABLE,
    url = process.env.ARKENIVA_MONGODB_URL;
  try {
    delete process.env.ARKENIVA_MONGODB_DISPOSABLE;
    delete process.env.ARKENIVA_MONGODB_URL;
    await assert.rejects(runMongoDBExample(), { code: 'EK_CONFIG_INVALID' });
    process.env.ARKENIVA_MONGODB_DISPOSABLE = '1';
    await assert.rejects(runMongoDBExample(), { code: 'EK_CONFIG_MISSING' });
    await assert.rejects(
      promisify(execFile)(process.execPath, ['dist/main.js'], { env: process.env }),
      (cause: unknown) => {
        assert.ok(cause && typeof cause === 'object' && 'stderr' in cause);
        const safe = JSON.parse(String(cause.stderr));
        assert.equal(safe.code, 'EK_CONFIG_MISSING');
        assert.equal(safe.cause, undefined);
        assert.equal(safe.stack, undefined);
        return true;
      },
    );
  } finally {
    if (disposable === undefined) delete process.env.ARKENIVA_MONGODB_DISPOSABLE;
    else process.env.ARKENIVA_MONGODB_DISPOSABLE = disposable;
    if (url === undefined) delete process.env.ARKENIVA_MONGODB_URL;
    else process.env.ARKENIVA_MONGODB_URL = url;
  }
});
