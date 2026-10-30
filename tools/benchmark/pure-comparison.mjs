// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork, execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { arch, cpus, platform, release } from 'node:os';
import { basename, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { types } from 'node:util';
import { runOrder } from './http-analysis.mjs';

export async function runPureComparison(definition, args = process.argv.slice(2)) {
  assert.ok(
    args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
    'Use --verify or --smoke with a fresh absolute external report directory',
  );
  assert.ok(
    definition && typeof definition === 'object' && !types.isProxy(definition),
    'The comparison definition must be trusted data',
  );
  const declaredSupervision = Object.getOwnPropertyDescriptor(definition, 'superviseProcessTree');
  assert.ok(
    !declaredSupervision || 'value' in declaredSupervision,
    'Process-tree supervision must be a captured boolean',
  );
  const superviseProcessTree = declaredSupervision?.value;
  assert.ok(
    superviseProcessTree === undefined || typeof superviseProcessTree === 'boolean',
    'Process-tree supervision must be a captured boolean',
  );
  const declaredTimeout = Object.getOwnPropertyDescriptor(definition, 'profileTimeoutMs');
  assert.ok(
    !declaredTimeout || 'value' in declaredTimeout,
    'The supervised profile budget must be a captured integer',
  );
  const configuredTimeout = declaredTimeout?.value;
  assert.ok(
    configuredTimeout === undefined ||
      (Number.isSafeInteger(configuredTimeout) &&
        configuredTimeout >= 30000 &&
        configuredTimeout <= 120000),
    'The supervised profile budget must be an integer from 30000 to 120000 milliseconds',
  );
  assert.ok(
    configuredTimeout === undefined || superviseProcessTree === true,
    'A custom profile budget requires explicit process-tree supervision',
  );
  const profileTimeoutMs = configuredTimeout === undefined ? 30000 : configuredTimeout;
  const supervisedMeasurement = superviseProcessTree === true && args[0] === '--smoke';
  assert.ok(
    !supervisedMeasurement || definition.trustAnchorFile === undefined,
    'Supervised comparison does not support trustAnchorFile',
  );
  const supervise = supervisedMeasurement
    ? (await import('./supervised-resources.mjs')).runSupervisedWorker
    : undefined;
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
  const fixture = definition.fixture,
    privacyValues = definition.privacyValues;
  assert.ok(privacyValues.every((value) => typeof value === 'string' && value.length > 0));
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
      for (const value of privacyValues)
        assert.equal(encoded.includes(value), false, 'Input data reached telemetry');
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
      let result;
      if (supervise) {
        const { message, resource } = await supervise(
          definition.worker,
          { mode, fixture, measure: true, endpoint },
          { timeoutMs: profileTimeoutMs },
        );
        assert.equal(message?.ok, true, 'The supervised comparison workload failed');
        assert.equal(resource.scope, 'whole-supervised-lifecycle');
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.pythonObserverIncluded, false);
        assert.equal(resource.externalServerResourcesIncluded, false);
        assert.equal(
          resource.descendantDiscoveryQuality.inaccessibleReads,
          0,
          'Supervised discovery coverage is incomplete',
        );
        assert.equal(
          resource.descendantDiscoveryQuality.traversalLimitExceeded,
          false,
          'Supervised discovery coverage is incomplete',
        );
        assert.equal(
          resource.rssReadQuality.inaccessibleReads,
          0,
          'Supervised RSS coverage is incomplete',
        );
        assert.equal(
          resource.rssReadQuality.allObservedReadsAccessible,
          true,
          'Supervised RSS coverage is incomplete',
        );
        for (const name of [
          'elapsedMs',
          'userCpuSeconds',
          'systemCpuSeconds',
          'largestSingleProcessRssBytes',
          'sampledSummedRssPeakBytes',
          'sampledLargestSingleRssBytes',
          'maxSamplingGapMs',
        ])
          assert.ok(
            Number.isFinite(resource[name]) && resource[name] >= 0,
            'Supervised resource observations are invalid',
          );
        result = { ...message.result, processTreeResource: resource };
      } else
        result = await new Promise((done, reject) => {
          const child = fork(definition.worker, [], {
            execPath: process.execPath,
            execArgv: ['--max-old-space-size=256'],
            env: {
              NODE_ENV: 'test',
              LANG: 'C.UTF-8',
              TZ: 'UTC',
              ...(definition.trustAnchorFile
                ? { NODE_EXTRA_CA_CERTS: definition.trustAnchorFile }
                : {}),
            },
            stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
          });
          active = child;
          let message, failure;
          const timer = setTimeout(() => {
            failure = new Error('The isolated pure-helper workload exceeded its deadline');
            child.kill('SIGKILL');
          }, 30000);
          child.once('message', (value) => {
            message = value;
          });
          child.once('error', () => {
            failure = new Error('The isolated pure-helper workload could not start');
          });
          child.once('close', (code) => {
            clearTimeout(timer);
            active = undefined;
            if (failure || code !== 0 || message?.ok !== true)
              reject(failure ?? new Error('The isolated pure-helper workload failed'));
            else done(message.result);
          });
          child.send({ mode, fixture, measure: args[0] === '--smoke', endpoint });
        });
      assert.equal(result.mode, mode);
      records.push(result);
    }
    const report = {
      scenarioId: definition.scenarioId,
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
      inputs: definition.inputs,
      observationCoverage: definition.observationCoverage,
      resourceCoverage:
        'Whole child process during measurement, including warmup and measurement-tool import; memory uses interval sampling and endpoints. GC callbacks and event-loop histograms may have no samples for a short run.',
      ...(supervisedMeasurement
        ? {
            ...(configuredTimeout === undefined ? {} : { profileTimeoutMs }),
            processTreeResourceCoverage:
              'Separate whole-supervised-lifecycle user/system CPU in seconds includes Node bridge/worker/native descendants, startup, verification, warmup, measurement, export and cleanup. RSS bytes distinguish sampled non-atomic process sums from largest single-process RSS; shared pages may repeat and brief peaks may be missed. Python observer, parent/collector and external servers are excluded. Inaccessible or truncated discovery/RSS observations are refused; vanished short-lived observations remain explicit. Existing measured-window worker resources retain their original meaning.',
          }
        : {}),
      limitations:
        definition.limitations ??
        'Local microcomparison with timer overhead; no entropy guarantee, distributed ordering guarantee, confidence interval, release budget, five repetitions or soak claim.',
      collector: { receivedBodies, totalBytes, [definition.privacyField]: 0 },
      records,
    };
    const encoded = JSON.stringify(report, null, 2) + '\n';
    for (const value of privacyValues) assert.equal(encoded.includes(value), false);
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
    return report;
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
}
