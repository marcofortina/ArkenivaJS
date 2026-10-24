import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { runMysqlOrdersExample } from '../../dist/main.js';

test('The MySQL guide rejects missing disposable configuration before creating resources and prints a safe CLI error', async () => {
  const previous = {
    marker: process.env.ARKENIVA_MYSQL_DISPOSABLE,
    url: process.env.ARKENIVA_MYSQL_URL,
  };
  try {
    delete process.env.ARKENIVA_MYSQL_DISPOSABLE;
    delete process.env.ARKENIVA_MYSQL_URL;
    await assert.rejects(
      runMysqlOrdersExample(),
      (error: unknown) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
    );
    process.env.ARKENIVA_MYSQL_DISPOSABLE = '1';
    await assert.rejects(
      runMysqlOrdersExample(),
      (error: unknown) => error instanceof KitError && error.code === 'EK_CONFIG_MISSING',
    );
    await assert.rejects(
      promisify(execFile)(process.execPath, ['dist/main.js'], { env: process.env }),
      (error: unknown) => {
        assert.ok(error && typeof error === 'object' && 'stderr' in error);
        const safe = JSON.parse(String(error.stderr));
        assert.equal(safe.code, 'EK_CONFIG_MISSING');
        assert.equal(safe.stack, undefined);
        assert.equal(safe.cause, undefined);
        return true;
      },
    );
  } finally {
    for (const [key, value] of [
      ['ARKENIVA_MYSQL_DISPOSABLE', previous.marker],
      ['ARKENIVA_MYSQL_URL', previous.url],
    ] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
