// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { serialize, deserialize } from 'node:v8';

// Only this Node process exchanges native advanced IPC with the actual worker.
// The Linux supervisor treats the ordinary stdin/stdout envelope as opaque data.
let worker;
try {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    assert.ok(bytes <= 2097152);
    chunks.push(chunk);
  }
  const config = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const input = Buffer.from(config.inputBase64, 'base64');
  assert.ok(input.length <= config.maxMessageBytes);
  worker = fork(config.worker, [], {
    execPath: process.execPath,
    execArgv: ['--max-old-space-size=256'],
    env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
    serialization: 'advanced',
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  let result,
    invalid = false;
  worker.on('message', (message) => {
    try {
      assert.equal(result, undefined);
      const encoded = serialize(message);
      assert.ok(encoded.length <= config.maxMessageBytes);
      result = encoded.toString('base64');
    } catch {
      invalid = true;
      worker.kill('SIGKILL');
    }
  });
  worker.on('error', () => {
    invalid = true;
    worker.kill('SIGKILL');
  });
  worker.once('close', (code) => {
    if (invalid || code !== 0 || result === undefined) process.exitCode = 1;
    else process.stdout.write(JSON.stringify({ resultBase64: result }) + '\n');
  });
  worker.send(deserialize(input), (error) => {
    if (error) {
      invalid = true;
      worker.kill('SIGKILL');
    }
  });
} catch {
  worker?.kill('SIGKILL');
  // Neither worker exceptions nor opaque fixture bytes enter diagnostic output.
  process.exitCode = 1;
}
