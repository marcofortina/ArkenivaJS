// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork, execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { arch, cpus, platform, release } from 'node:os';
import { basename, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { v7 } from 'uuid';
import { runOrder } from './http-analysis.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const root = await realpath(fileURLToPath(new URL('../../', import.meta.url))),
  requested = resolve(args[1]);
assert.equal(requested, args[1], 'The evidence directory must be absolute and normalized');
const parent = await realpath(dirname(requested)),
  directory = resolve(parent, basename(requested));
assert.ok(
  directory !== root && !directory.startsWith(root + sep),
  'Evidence must remain outside the source repository',
);
await mkdir(directory, { mode: 0o700 });
const fixture = { v4: randomUUID(), v7: v7({}) };
while (fixture.v4.toUpperCase() === fixture.v4) fixture.v4 = randomUUID();
const records = [];
let active,
  receivedBodies = 0,
  totalBytes = 0;
const collector = createServer((request, response) => {
  void (async () => {
    assert.ok(['/v1/metrics', '/v1/traces'].includes(request.url));
    assert.equal(request.method, 'POST');
    const chunks = [];
    let bytes = 0;
    for await (const chunk of request) {
      bytes += chunk.length;
      totalBytes += chunk.length;
      assert.ok(
        bytes <= 1048576 && totalBytes <= 4194304,
        'The owned collector capacity is exceeded',
      );
      chunks.push(chunk);
    }
    const encoded = JSON.stringify(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    for (const value of Object.values(fixture))
      assert.equal(encoded.includes(value), false, 'Identifier data reached telemetry');
    receivedBodies++;
    response.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  })().catch(() => response.writeHead(500).end());
});
await new Promise((done, reject) => {
  collector.once('error', reject);
  collector.listen(0, '127.0.0.1', done);
});
const endpoint = 'http://127.0.0.1:' + collector.address().port;
try {
  for (const { mode } of runOrder(1, 137)) {
    const result = await new Promise((done, reject) => {
      const child = fork(new URL('./identifiers-worker.mjs', import.meta.url), [], {
        execPath: process.execPath,
        execArgv: ['--max-old-space-size=256'],
        env: { NODE_ENV: 'test', LANG: 'C.UTF-8', TZ: 'UTC' },
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      });
      active = child;
      let message, failure;
      const timer = setTimeout(() => {
        failure = new Error('The isolated identifier workload exceeded its deadline');
        child.kill('SIGKILL');
      }, 30000);
      child.once('message', (value) => {
        message = value;
      });
      child.once('error', () => {
        failure = new Error('The isolated identifier workload could not start');
      });
      child.once('close', (code) => {
        clearTimeout(timer);
        active = undefined;
        if (failure || code !== 0 || message?.ok !== true)
          reject(failure ?? new Error('The isolated identifier workload failed'));
        else done(message.result);
      });
      child.send({ mode, fixture, measure: args[0] === '--smoke', endpoint });
    });
    assert.equal(result.mode, mode);
    records.push(result);
  }
  const report = {
    scenarioId: 'identifier-microcomparison',
    gitSha: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
    workingTreeDirty:
      execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim()
        .length > 0,
    nodeVersion: process.version,
    measured: args[0] === '--smoke',
    releaseGate: false,
    repetitions: 1,
    hardware: {
      cpuModel: cpus()[0]?.model ?? null,
      logicalCpus: cpus().length,
      platform: platform(),
      kernel: release(),
      architecture: arch(),
    },
    inputs: {
      operations: [
        'uuidV4',
        'uuidV7',
        'parseV4',
        'parseV7',
        'validateV4',
        'validateV7',
        'rejectNoncanonical',
      ],
      fixedCanonicalFixtures: 2,
      uuidVersion: '14.0.3',
      tinybenchVersion: '6.2.2',
      concurrency: 1,
    },
    observationCoverage:
      'Identifier calls are pure helpers without automatic per-call spans or metrics; diagnostic modes install the actual SDK without adding artificial observation work.',
    resourceCoverage:
      'Whole child process during measurement, including warmup and measurement-tool import; memory uses interval sampling and endpoints. GC callbacks and event-loop histograms may have no samples for a short run.',
    limitations:
      'Local microcomparison with timer overhead; no entropy guarantee, distributed ordering guarantee, confidence interval, release budget, five repetitions or soak claim.',
    collector: { receivedBodies, totalBytes, identifierOccurrences: 0 },
    records,
  };
  const encoded = JSON.stringify(report, null, 2) + '\n';
  for (const value of Object.values(fixture)) assert.equal(encoded.includes(value), false);
  await writeFile(resolve(directory, 'report.json'), encoded, { mode: 0o600, flag: 'wx' });
  console.log(
    JSON.stringify({
      status: 'PASS',
      measured: report.measured,
      releaseGate: false,
      profiles: records.length,
      report: resolve(directory, 'report.json'),
    }),
  );
} finally {
  if (active) {
    const child = active;
    await new Promise((done) => {
      child.once('close', done);
      child.kill('SIGKILL');
    });
  }
  collector.closeAllConnections();
  await new Promise((done) => collector.close(done));
}
