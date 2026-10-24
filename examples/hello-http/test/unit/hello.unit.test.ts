import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { Writable } from 'node:stream';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createHelloApplication } from '../../src/main.js';

async function freePort() {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const value = server.address();
  assert.ok(value && typeof value === 'object');
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return value.port;
}
test('Hello guide executes typed REST, outbound request and safe shutdown over real sockets', async () => {
  const lines: string[] = [];
  const destination = new Writable({
    write(chunk, _encoding, done) {
      lines.push(String(chunk));
      done();
    },
  });
  const { app, origin } = await createHelloApplication({ port: await freePort(), destination });
  try {
    await app.start();
    for (const path of ['/hello/Ada', '/proxy/Ada'])
      assert.deepEqual(await (await fetch(origin + path)).json(), { greeting: 'Hello Ada' });
    assert.equal((await fetch(origin + '/missing')).status, 404);
    assert.equal((await fetch(origin + '/livez')).status, 200);
    assert.equal((await fetch(origin + '/readyz')).status, 200);
    assert.equal(app.api.openApiDocument().openapi, '3.1.0');
    const inflight = app.http.get(origin + '/proxy/Grace');
    const drained = inflight.then(async (response) => {
      assert.equal(response.status, 200);
      return response.json();
    });
    await drained;
    assert.ok(
      lines
        .map((line) => JSON.parse(line))
        .some((line) => line.route === '/proxy/:name' && line.requestId),
    );
  } finally {
    await app.stop();
    destination.destroy();
  }
  assert.equal(app.state, 'CLOSED');
});
test('The documented CLI serves curl output and terminates on SIGTERM', async () => {
  const port = await freePort();
  const child = spawn(process.execPath, ['dist/main.js'], {
    env: { ...process.env, ARKENIVAJS_PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exit = once(child, 'exit');
  let output = '',
    errors = '';
  child.stdout.on('data', (data) => {
    output += String(data);
  });
  child.stderr.on('data', (data) => {
    errors += String(data);
  });
  try {
    for (let count = 0; count < 100 && !output.includes('HTTP example ready'); count++)
      await delay(20);
    assert.ok(output.includes('HTTP example ready'), errors);
    const body = execFileSync(
      'curl',
      ['--fail', '--silent', '--show-error', `http://127.0.0.1:${port}/proxy/Ada`],
      { encoding: 'utf8', timeout: 5000 },
    );
    assert.deepEqual(JSON.parse(body), { greeting: 'Hello Ada' });
    child.kill('SIGTERM');
    const [status] = await Promise.race([
      exit,
      delay(5000, undefined, { ref: false }).then(() => {
        throw new Error('CLI shutdown did not complete');
      }),
    ]);
    assert.equal(status, 0);
  } finally {
    if (child.exitCode === null) child.kill('SIGKILL');
  }
});
