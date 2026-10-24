import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';
const evidence = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const expected = Object.values(evidence);
const requiredKeys = [
  'service.name',
  'service.version',
  'service.instance.id',
  'deployment.environment.name',
  'process.pid',
  'k8s.namespace.name',
  'k8s.pod.name',
  'k8s.container.name',
  'k8s.node.name',
];
let log;
if (process.argv[3] === '--docker') {
  const deadline = performance.now() + 10_000;
  while (true) {
    log = execFileSync(
      'docker',
      [
        'compose',
        '-f',
        'packages/telemetry/test/fixtures/compose.yaml',
        'logs',
        '--no-color',
        'collector',
      ],
      { encoding: 'utf8', maxBuffer: 10_485_760 },
    );
    if (expected.every((value) => log.includes(value)) || performance.now() >= deadline) break;
    await delay(100);
  }
} else log = readFileSync(process.argv[3], 'utf8');
for (const value of [...expected, ...requiredKeys])
  assert.ok(log.includes(value), `Collector output is missing expected metadata: ${value}`);
assert.ok(!log.includes('fake-private-database-token'));
console.log(
  'Actual collector output contains the expected trace, metric and workload resource metadata',
);
