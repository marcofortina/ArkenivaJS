// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { records } from '../fixtures/events.js';
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
import {
  mkdtemp,
  readFile,
  writeFile,
  chmod,
  stat,
  rm,
  symlink,
  readdir,
  unlink,
  mkdir,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createJsonlExporter, parseMeteringEvent } from '@arkenivajs/metering';
const rows = (text: string) =>
  text
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => parseMeteringEvent(JSON.parse(line)));

test('EK-METER-001 real JSONL append holds a private exclusive lock, fsyncs records and releases ownership for restart', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-meter-'));
  const path = join(workspace, 'events.jsonl');
  const events = await records(3);
  const exporter = await createJsonlExporter({ workspace, path: 'events.jsonl' });
  try {
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal((await stat(path + '.lock')).mode & 0o777, 0o600);
    await assert.rejects(
      createJsonlExporter({ workspace, path: 'events.jsonl' }),
      code('EK_METER_EXPORT'),
    );
    await exporter.export(events.slice(0, 2), {});
    assert.deepEqual(rows(await readFile(path, 'utf8')), events.slice(0, 2));
    await assert.rejects(
      exporter.export([{ ...events[0], private: 'fake-secret' } as never], {}),
      code('EK_METER_EXPORT'),
    );
    assert.equal(rows(await readFile(path, 'utf8')).length, 2);
    const writing = exporter.export(events.slice(2), {});
    await assert.rejects(
      exporter.export(events, {}),
      (error) => code('EK_METER_EXPORT')(error) && (error as KitError).retryable,
    );
    await writing;
    await exporter.close();
    await exporter.close();
    await assert.rejects(stat(path + '.lock'));
    const reopened = await createJsonlExporter({ workspace, path: 'events.jsonl' });
    await reopened.export(events.slice(0, 1), {});
    await reopened.close();
    assert.equal(rows(await readFile(path, 'utf8')).length, 4);
    await assert.rejects(exporter.export(events, {}), code('EK_METER_EXPORT'));
  } finally {
    await exporter.close();
    await rm(workspace, { recursive: true, force: true });
  }
});

test('EK-METER-001 size and elapsed rotation retain bounded private complete JSON Lines files', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-rotate-'));
  const events = await records(350);
  const exporter = await createJsonlExporter({
    workspace,
    path: 'events.jsonl',
    maxFileBytes: 65_536,
    retainedFiles: 2,
  });
  try {
    await exporter.export(events, {});
    await exporter.close();
    const names = (await readdir(workspace)).filter((name) => name.startsWith('events.jsonl'));
    assert.equal(names.length, 3);
    let retained = 0;
    const ids = new Set<string>();
    for (const name of names) {
      const path = join(workspace, name);
      const info = await stat(path);
      assert.ok(info.size <= 65_536);
      assert.equal(info.mode & 0o777, 0o600);
      for (const event of rows(await readFile(path, 'utf8'))) {
        assert.ok(!ids.has(event.eventId));
        ids.add(event.eventId);
        retained++;
      }
    }
    assert.ok(retained < events.length && retained > 0);
    const timed = await createJsonlExporter({
      workspace,
      path: 'timed.jsonl',
      rotationIntervalMs: 1,
    });
    await timed.export(events.slice(0, 1), {});
    await delay(5);
    await timed.export(events.slice(1, 2), {});
    await timed.close();
    assert.equal(rows(await readFile(join(workspace, 'timed.jsonl.1'), 'utf8')).length, 1);
  } finally {
    await exporter.close();
    await rm(workspace, { recursive: true, force: true });
  }
});

test('EK-METER-001 JSONL refuses escaped/symlinked/insecure/torn files without altering their contents', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-file-policy-'));
  const outside = await mkdtemp(join(tmpdir(), 'arkeniva-outside-'));
  try {
    await writeFile(join(outside, 'protected'), 'fake-private', { mode: 0o600 });
    await symlink(join(outside, 'protected'), join(workspace, 'link'));
    for (const path of ['../escape', 'link'])
      await assert.rejects(createJsonlExporter({ workspace, path }), code('EK_METER_EXPORT'));
    await mkdir(join(workspace, 'private'));
    await symlink(join(workspace, 'private'), join(workspace, 'directory-link'));
    await assert.rejects(
      createJsonlExporter({ workspace, path: 'directory-link/events' }),
      code('EK_METER_EXPORT'),
    );
    await writeFile(join(workspace, 'public'), 'unchanged\n', { mode: 0o644 });
    // Creation modes are filtered by umask; establish the unsafe permission case explicitly.
    await chmod(join(workspace, 'public'), 0o644);
    assert.equal((await stat(join(workspace, 'public'))).mode & 0o777, 0o644);
    await assert.rejects(
      createJsonlExporter({ workspace, path: 'public' }),
      code('EK_METER_EXPORT'),
    );
    assert.equal(await readFile(join(workspace, 'public'), 'utf8'), 'unchanged\n');
    await writeFile(join(workspace, 'torn'), '{"partial":', { mode: 0o600 });
    await assert.rejects(createJsonlExporter({ workspace, path: 'torn' }), code('EK_METER_EXPORT'));
    assert.equal(await readFile(join(workspace, 'torn'), 'utf8'), '{"partial":');
    await chmod(join(workspace, 'private'), 0o777);
    await assert.rejects(
      createJsonlExporter({ workspace, path: 'private/events' }),
      code('EK_METER_EXPORT'),
    );
    assert.equal(await readFile(join(outside, 'protected'), 'utf8'), 'fake-private');
    for (const policy of [
      { path: '/absolute' },
      { path: 'valid', maxFileBytes: 1 },
      { path: 'valid', retainedFiles: 0 },
      { path: 'valid', rotationIntervalMs: 0 },
    ])
      await assert.rejects(
        createJsonlExporter({ workspace, ...policy }),
        code('EK_CONFIG_INVALID'),
      );
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('EK-METER-001 file ownership loss and cancellation poison the writer instead of acknowledging uncertain writes', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-file-loss-'));
  const events = await records();
  const exporter = await createJsonlExporter({ workspace, path: 'events' });
  try {
    await unlink(join(workspace, 'events'));
    await assert.rejects(exporter.export(events, {}), code('EK_METER_EXPORT'));
    await assert.rejects(exporter.export(events, {}), code('EK_METER_EXPORT'));
    await exporter.close();
    const cancelled = await createJsonlExporter({ workspace, path: 'cancelled' });
    await assert.rejects(
      cancelled.export(events, { signal: AbortSignal.abort() }),
      code('EK_ABORTED'),
    );
    await cancelled.close();
    assert.equal(await readFile(join(workspace, 'cancelled'), 'utf8'), '');
  } finally {
    await exporter.close();
    await rm(workspace, { recursive: true, force: true });
  }
});

test('EK-METER-001 actual file-size exhaustion rejects acknowledgment and truncates the incomplete record', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-file-exhaustion-'));
  const original = (await records())[0]!;
  const event = {
    ...original,
    counters: Object.fromEntries(
      Array.from({ length: 32 }, (_, index) => [
        'resource.' + index,
        { unit: 'items', source: 'observed', value: 1 },
      ]),
    ),
  };
  const script = fileURLToPath(
    new URL('../../../test/fixtures/file-exhaustion.mjs', import.meta.url),
  );
  try {
    const result = await promisify(execFile)(
      'bash',
      [
        '--noprofile',
        '--norc',
        '-c',
        'original_limit=$(prlimit --pid $$ --fsize --noheadings --raw --output SOFT,HARD); ulimit -S -f 1; exec "$@" "$original_limit"',
        'meter-file-limit',
        process.execPath,
        script,
        workspace,
        JSON.stringify(event),
      ],
      { timeout: 10_000 },
    );
    assert.match(result.stdout, /incomplete data was rolled back/);
    assert.equal(result.stderr, '');
    await assert.rejects(stat(join(workspace, 'limited.jsonl.lock')));
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('EK-METER-001 cleanup refuses to delete a replaced file lock and still closes its own resources', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-lock-replacement-'));
  const exporter = await createJsonlExporter({ workspace, path: 'events.jsonl' });
  try {
    await unlink(join(workspace, 'events.jsonl.lock'));
    await writeFile(join(workspace, 'events.jsonl.lock'), 'replacement', { mode: 0o600 });
    await assert.rejects(exporter.close(), code('EK_METER_EXPORT'));
    assert.equal(await readFile(join(workspace, 'events.jsonl.lock'), 'utf8'), 'replacement');
  } finally {
    await exporter.close().catch(() => undefined);
    await rm(workspace, { recursive: true, force: true });
  }
});
