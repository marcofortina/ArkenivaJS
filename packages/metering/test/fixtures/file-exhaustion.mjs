import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';
import { createJsonlExporter } from '@arkenivajs/metering';

// Only this disposable child receives the limit; retain coverage through normal process exit.
const [workspace, encoded, previous] = process.argv.slice(2);
const originalLimit = previous.trim().split(/\s+/).join(':');
process.on('SIGXFSZ', () => {});
try {
  const exporter = await createJsonlExporter({ workspace, path: 'limited.jsonl' });
  let rejected = false;
  try {
    await exporter.export([JSON.parse(encoded)], {});
  } catch (error) {
    assert.equal(error.code, 'EK_METER_EXPORT');
    rejected = true;
  } finally {
    await exporter.close();
  }
  assert.ok(rejected);
  assert.equal((await stat(join(workspace, 'limited.jsonl'))).size, 0);
} finally {
  // Restore the child's original limit before V8 writes its coverage file at exit.
  execFileSync('prlimit', ['--pid', String(process.pid), '--fsize=' + originalLimit]);
}
console.log('Kernel file-size limit rejected the write and incomplete data was rolled back');
