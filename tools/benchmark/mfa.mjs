// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { fork, execFileSync } from 'node:child_process';
import { appendFile, mkdir, readFile, writeFile, stat, realpath } from 'node:fs/promises';
import { resolve, join, isAbsolute, relative, dirname, basename, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cpus, totalmem, release, platform, arch } from 'node:os';
import { connectBrowser } from '../../examples/postgres/dist-test/browser/cdp.js';
import { runOrder, pairedComparison } from './http-analysis.mjs';
import { countSensitiveValues } from './mfa-privacy.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--smoke', '--full'].includes(args[0]),
  'Use --smoke ABSOLUTE_OUTPUT or --full ABSOLUTE_OUTPUT',
);
assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
assert.equal(process.env.ARKENIVA_WEBAUTHN_BROWSER_DISPOSABLE, '1');
assert.ok(process.env.ARKENIVA_WEBAUTHN_BROWSER_URL);
const output = join(await realpath(dirname(resolve(args[1]))), basename(args[1]));
const outputRelative = relative(root, output);
assert.ok(
  isAbsolute(args[1]) && (outputRelative === '..' || outputRelative.startsWith('..' + sep)),
  'Benchmark evidence must remain outside the product repository',
);
await assert.rejects(stat(output), { code: 'ENOENT' });
await mkdir(output, { mode: 0o700 });
const origin = 'http://localhost:19377',
  client = await readFile(
    new URL('../dist/bundle/index.umd.min.js', import.meta.resolve('@simplewebauthn/browser')),
  );
const frontend = createServer((request, response) => {
  response.setHeader('cache-control', 'no-store');
  response.setHeader('x-content-type-options', 'nosniff');
  response.setHeader(
    'content-security-policy',
    "default-src 'none'; script-src 'self'; frame-ancestors 'none'",
  );
  if (request.method !== 'GET' || !['/', '/client.js'].includes(request.url))
    return response.writeHead(404).end();
  response.setHeader(
    'content-type',
    request.url === '/client.js' ? 'text/javascript' : 'text/html',
  );
  response.end(
    request.url === '/client.js'
      ? client
      : '<!doctype html><title>Disposable MFA benchmark</title><script defer src="/client.js"></script>',
  );
});
let currentDirectory,
  acceptedBytes = 0,
  activeRequests = 0,
  failedWrites = 0,
  received = 0;
const writes = new Set();
let writer = Promise.resolve();
const collector = createServer(async (request, response) => {
  if (
    request.method !== 'POST' ||
    !['/v1/traces', '/v1/metrics'].includes(request.url) ||
    activeRequests >= 8
  )
    return response.writeHead(429).end();
  activeRequests++;
  try {
    const chunks = [];
    let bytes = 0;
    request.setTimeout(5000, () => request.destroy());
    for await (const chunk of request) {
      bytes += chunk.length;
      if (bytes > 1048576 || acceptedBytes + bytes > 100 * 1048576)
        throw new Error('OTLP fixture capacity reached');
      chunks.push(chunk);
    }
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert.ok(currentDirectory);
    const writing = writer.then(() =>
      appendFile(join(currentDirectory, 'otlp.jsonl'), JSON.stringify(data) + '\n', {
        mode: 0o600,
      }),
    );
    writer = writing.catch(() => undefined);
    writes.add(writing);
    try {
      await writing;
    } finally {
      writes.delete(writing);
    }
    acceptedBytes += bytes;
    received++;
    response.setHeader('content-type', 'application/json');
    response.end('{}');
  } catch {
    failedWrites++;
    response.writeHead(400).end('{}');
  } finally {
    activeRequests--;
  }
});
async function listen(server, port) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
}
const readPrivacy = async (directory, fingerprints) => {
  let data;
  try {
    data = await readFile(join(directory, 'otlp.jsonl'), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return { leaks: 0, requests: 0 };
    throw error;
  }
  let leaks = 0;
  const lines = data.trim().split('\n').filter(Boolean);
  for (const line of lines) leaks += countSensitiveValues(JSON.parse(line), fingerprints);
  return { leaks, requests: lines.length };
};
const results = [],
  startedAt = new Date().toISOString(),
  full = args[0] === '--full';
const gitSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
const workingTreeDirty =
  execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim().length > 0;
try {
  await listen(frontend, 19377);
  await listen(collector, 0);
  const collectorUrl = 'http://127.0.0.1:' + collector.address().port;
  for (const { mode } of runOrder(1, 137)) {
    const directory = join(output, mode.toLowerCase());
    await mkdir(directory, { mode: 0o700 });
    currentDirectory = directory;
    const page = await connectBrowser(process.env.ARKENIVA_WEBAUTHN_BROWSER_URL);
    let child,
      privacyHashes = [],
      failure;
    try {
      await page.command('Page.enable');
      await page.command('WebAuthn.enable', { enableUI: false });
      const authenticator = await page.command('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      await page.command('Page.navigate', { url: origin });
      assert.equal(
        await page.evaluate(
          'new Promise(resolve=>{const ready=()=>typeof SimpleWebAuthnBrowser==="object"?resolve(true):setTimeout(ready,20);ready();})',
        ),
        true,
      );
      child = fork(new URL('./mfa-worker.mjs', import.meta.url), [], {
        cwd: root,
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        env: {
          ...process.env,
          ARKENIVA_MFA_WORKER_SETTINGS: JSON.stringify({
            mode,
            full,
            directory,
            origin,
            collector: collectorUrl,
            browser: page.version,
          }),
        },
      });
      let unexpectedOutput = 0;
      child.stdout.on('data', (chunk) => {
        unexpectedOutput += chunk.length;
      });
      child.stderr.on('data', (chunk) => {
        unexpectedOutput += chunk.length;
      });
      const pending = new Set();
      child.on('message', (message) => {
        if (message?.kind === 'failed') {
          failure = { stage: message.stage, frames: message.frames };
          return;
        }
        if (message?.kind === 'done') return;
        const handling = (async () => {
          try {
            let result;
            if (['registration', 'authentication'].includes(message.kind))
              result = await page.evaluate(
                'SimpleWebAuthnBrowser.' +
                  (message.kind === 'registration' ? 'startRegistration' : 'startAuthentication') +
                  '(' +
                  JSON.stringify({ optionsJSON: message.body.optionsJSON }) +
                  ')',
              );
            else if (message.kind === 'counterless') {
              await page.command('WebAuthn.setCredentialProperties', {
                authenticatorId: authenticator.authenticatorId,
                credentialId: Buffer.from(message.body.credentialId, 'base64url').toString(
                  'base64',
                ),
                signCount: -1,
              });
              result = true;
            } else if (message.kind === 'privacy') {
              privacyHashes = message.body.fingerprints;
              await Promise.all(writes);
              result = await readPrivacy(directory, privacyHashes);
            } else throw new Error('Unknown benchmark request');
            if (child.connected) child.send({ id: message.id, result });
          } catch {
            if (child.connected) child.send({ id: message.id, failed: true });
          }
        })();
        pending.add(handling);
        void handling.finally(() => pending.delete(handling));
      });
      const timer = setTimeout(
        () => {
          failure = { stage: 'worker-timeout' };
          child.kill('SIGTERM');
        },
        full ? 800000 : 60000,
      );
      const code = await new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('close', resolve);
      });
      clearTimeout(timer);
      await Promise.all(pending);
      await Promise.all(writes);
      if (code !== 0 || failure || unexpectedOutput)
        throw new Error(
          'MFA benchmark worker failed: ' +
            JSON.stringify({ mode, code, failure, unexpectedOutput }),
        );
      assert.equal((await readPrivacy(directory, privacyHashes)).leaks, 0);
      const report = JSON.parse(await readFile(join(directory, 'results.json'), 'utf8'));
      results.push(report);
    } finally {
      if (child?.exitCode === null) child.kill('SIGTERM');
      await page.close();
    }
  }
  const baseline = results.find((value) => value.mode === 'BASELINE');
  const comparisons = results
    .filter((value) => value.mode !== 'BASELINE')
    .flatMap((value) =>
      value.records.map((record) => {
        const before = baseline.records.find((entry) => entry.scenarioId === record.scenarioId);
        return {
          mode: value.mode,
          scenarioId: record.scenarioId,
          p95: {
            ...pairedComparison([before.latencyMs.p95], [record.latencyMs.p95]),
            confidence95Percent: null,
          },
          releaseGate: false,
        };
      }),
    );
  assert.equal(failedWrites, 0);
  await writeFile(
    join(output, 'report.json'),
    JSON.stringify(
      {
        scenarioId: 'mfa-durable-four-mode',
        gitSha,
        workingTreeDirty,
        nodeVersion: process.version,
        startedAt,
        hardware: {
          cpu: cpus()[0]?.model,
          cpuCount: cpus().length,
          totalMemoryBytes: totalmem(),
          os: platform(),
          kernel: release(),
          architecture: arch(),
          runnerType: process.env.ARKENIVA_BENCHMARK_RUNNER ?? 'unspecified',
          cpuAffinity:
            (await readFile('/proc/self/status', 'utf8').catch(() => '')).match(
              /^Cpus_allowed_list:\s*(.+)$/m,
            )?.[1] ?? null,
          governor:
            (
              await readFile('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor', 'utf8').catch(
                () => '',
              )
            ).trim() || null,
        },
        configuration: {
          full,
          runIterationCount: 1,
          randomSeed: 137,
          samplingRatioStandard: 0.1,
          samplingRatioDetailed: 1,
          browserImage:
            'mcr.microsoft.com/playwright:v1.64.0-noble@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f',
          databaseTls: 'verified disposable fixture',
          databaseImage: process.env.PG_FIXTURE_IMAGE ?? null,
          databaseImageIdentityObserved: false,
          nativeScope:
            'Direct upstream positive-path MFA verification with identical durable backing providers; not a bare SQL-driver comparison',
          quotaClock: 'trusted test clock',
        },
        measured: true,
        releaseGate: false,
        calibration:
          'Not established; dedicated matched-load repeated campaigns and soak remain separate',
        collector: {
          received,
          acceptedBytes,
          failedWrites,
          protocol:
            'real OTLP JSON export to a bounded controlled HTTP sink; no production backend persistence claim',
        },
        results,
        comparisons,
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600 },
  );
  console.log(
    JSON.stringify({
      status: 'PASS',
      modes: results.length,
      records: results.reduce((sum, value) => sum + value.records.length, 0),
      releaseGate: false,
      report: join(output, 'report.json'),
    }),
  );
} finally {
  for (const server of [frontend, collector]) {
    server.closeAllConnections();
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  }
}
