import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { modeDTO, runEtcdExample } from '../../dist/main.js';

test('The etcd consumer converts explicit JSON bytes and exact bigint metadata into a serializable DTO', () => {
  const value = {
    key: 'mode',
    value: new TextEncoder().encode('{"mode":"enabled"}'),
    revision: 9007199254740993n,
    version: 9007199254740995n,
  };
  const dto = modeDTO(value);
  assert.deepEqual(JSON.parse(JSON.stringify(dto)), {
    mode: 'enabled',
    revision: '9007199254740993',
    version: '9007199254740995',
  });
  assert.equal(Object.isFrozen(dto), true);
  assert.throws(() => modeDTO({ ...value, value: Uint8Array.from([255]) }));
  assert.throws(() => modeDTO({ ...value, value: new TextEncoder().encode('{"mode":false}') }), {
    code: 'EK_CONFIG_INVALID',
  });
});

test('The etcd consumer requires explicit live authorization and prints safe CLI errors', async () => {
  const disposable = process.env.ARKENIVA_ETCD_DISPOSABLE,
    url = process.env.ARKENIVA_ETCD_URL;
  try {
    delete process.env.ARKENIVA_ETCD_DISPOSABLE;
    delete process.env.ARKENIVA_ETCD_URL;
    await assert.rejects(runEtcdExample(), { code: 'EK_CONFIG_INVALID' });
    process.env.ARKENIVA_ETCD_DISPOSABLE = '1';
    await assert.rejects(runEtcdExample(), { code: 'EK_CONFIG_MISSING' });
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
    if (disposable === undefined) delete process.env.ARKENIVA_ETCD_DISPOSABLE;
    else process.env.ARKENIVA_ETCD_DISPOSABLE = disposable;
    if (url === undefined) delete process.env.ARKENIVA_ETCD_URL;
    else process.env.ARKENIVA_ETCD_URL = url;
  }
});
