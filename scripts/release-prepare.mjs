// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const versionPattern =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const workflows = ['ci.yml', 'security.yml', 'compatibility.yml', 'performance.yml'];

/** Verify an annotated release tag against one explicitly trusted owner key. */
export function verifyReleaseTag({ root, tag, publicKey, fingerprint, expectedCommit }) {
  assert.ok(typeof tag === 'string' && tag.length <= 128 && tag.startsWith('v'));
  const version = tag.slice(1);
  assert.match(version, versionPattern, 'An exact version tag is required');
  for (const identifier of version.split('+')[0].split('-').slice(1).join('-').split('.'))
    assert.ok(
      !/^0[0-9]+$/.test(identifier),
      'Numeric prerelease identifiers cannot have leading zeroes',
    );
  assert.ok(typeof fingerprint === 'string');
  assert.match(
    fingerprint,
    /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/,
    'A full owner fingerprint is required',
  );
  assert.ok(
    typeof publicKey === 'string' &&
      publicKey.length <= 65536 &&
      publicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') &&
      !publicKey.includes('PRIVATE KEY'),
    'Only an explicitly configured public verification key is accepted',
  );
  const isolatedEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_') && key !== 'GNUPGHOME'),
  );
  Object.assign(isolatedEnvironment, {
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_NO_REPLACE_OBJECTS: '1',
  });
  const git = (...args) =>
    execFileSync('git', args, {
      cwd: root,
      env: isolatedEnvironment,
      encoding: 'utf8',
      timeout: 15000,
    }).trim();
  assert.equal(
    git('status', '--porcelain=v1', '--untracked-files=all'),
    '',
    'Release source must be clean',
  );
  const ref = 'refs/tags/' + tag;
  assert.equal(git('cat-file', '-t', ref), 'tag', 'Lightweight release tags are rejected');
  const commit = git('rev-parse', '--verify', ref + '^{commit}');
  assert.match(commit, /^[0-9a-f]{40}$/);
  if (expectedCommit !== undefined) {
    assert.match(expectedCommit, /^[0-9a-f]{40}$/, 'A frozen release commit is required');
    assert.equal(commit, expectedCommit, 'The signed release identity changed during preparation');
    assert.equal(
      git('rev-parse', 'HEAD'),
      expectedCommit,
      'The built source differs from the frozen release commit',
    );
  }
  const header = git('cat-file', 'tag', ref).split('\n\n')[0].split('\n');
  assert.ok(
    header.includes('tag ' + tag) &&
      header.includes('type commit') &&
      header.includes('object ' + commit),
    'The signed annotation must name this exact tag and commit',
  );
  git('merge-base', '--is-ancestor', commit, 'refs/remotes/origin/main');
  const manifest = JSON.parse(git('show', commit + ':package.json'));
  assert.equal(manifest.version, version, 'Release tag and package version disagree');
  assert.equal(manifest.private, true, 'Preparation preserves the private workspace');
  const packages = git('ls-tree', '-r', '--name-only', commit, 'packages')
    .split('\n')
    .filter((path) => /^packages\/[^/]+\/package\.json$/.test(path));
  assert.ok(packages.length > 0, 'Framework packages are required');
  for (const path of packages) {
    const item = JSON.parse(git('show', commit + ':' + path));
    assert.equal(item.version, version, 'Framework package versions must remain in lockstep');
    assert.equal(item.private, true, 'Preparation must preserve private package metadata');
  }
  const home = mkdtempSync(join(tmpdir(), 'arkenivajs-release-key-'));
  try {
    const env = { ...isolatedEnvironment, GNUPGHOME: home };
    execFileSync('gpg', ['--batch', '--import-options', 'import-minimal', '--import'], {
      env,
      input: publicKey,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 15000,
    });
    const listing = execFileSync('gpg', ['--batch', '--with-colons', '--list-keys'], {
      env,
      encoding: 'utf8',
      timeout: 15000,
    });
    const primary = [];
    let wanted = false;
    for (const line of listing.split('\n')) {
      const parts = line.split(':');
      if (parts[0] === 'pub') wanted = true;
      else if (parts[0] === 'fpr' && wanted) {
        primary.push(parts[9]);
        wanted = false;
      }
    }
    assert.deepEqual(
      primary,
      [fingerprint],
      'The verification key must match the owner fingerprint',
    );
    const result = execFileSync(
      'git',
      ['-c', 'gpg.format=openpgp', '-c', 'gpg.program=gpg', 'verify-tag', '--raw', ref],
      {
        cwd: root,
        env,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 15000,
      },
    );
    void result;
    // A second status-only verification binds signing subkeys to the configured primary key.
    const signed = git('cat-file', 'tag', ref);
    const boundary = signed.indexOf('-----BEGIN PGP SIGNATURE-----');
    assert.ok(boundary > 0, 'An OpenPGP-signed annotated tag is required');
    const signature = join(home, 'signature.asc'),
      payload = join(home, 'payload');
    writeFileSync(signature, signed.slice(boundary) + '\n', { mode: 0o600 });
    writeFileSync(payload, signed.slice(0, boundary), { mode: 0o600 });
    const status = execFileSync(
      'gpg',
      ['--batch', '--status-fd=1', '--verify', signature, payload],
      {
        env,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 15000,
      },
    );
    assert.ok(
      !/\[GNUPG:\] (?:EXPKEYSIG|EXPSIG|REVKEYSIG|BADSIG|ERRSIG)\b/.test(status),
      'Expired, revoked or invalid signatures are rejected',
    );
    const valid = status.split('\n').filter((line) => line.startsWith('[GNUPG:] VALIDSIG '));
    assert.equal(valid.length, 1, 'Exactly one valid signature is required');
    const fields = valid[0].split(' ');
    assert.equal(fields.at(-1), fingerprint, 'The signature is not from the configured owner key');
  } finally {
    try {
      execFileSync('gpgconf', ['--homedir', home, '--kill', 'gpg-agent'], {
        stdio: 'ignore',
        timeout: 5000,
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
  return Object.freeze({ tag, version, commit, publicationAuthorized: false });
}

/** Require complete latest-attempt success on the exact release commit, with bounded pagination. */
export async function verifyReleaseChecks({ repository, commit, request, environment = false }) {
  assert.match(repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
  assert.match(commit, /^[0-9a-f]{40}$/);
  const list = async (path, key) => {
    const rows = [];
    let expected;
    for (let page = 1; page <= 100; page++) {
      const data = await request(
        path + (path.includes('?') ? '&' : '?') + 'per_page=100&page=' + page,
      );
      assert.ok(
        Number.isSafeInteger(data.total_count) &&
          data.total_count >= 0 &&
          data.total_count <= 10000,
        'Unexpected check pagination',
      );
      expected ??= data.total_count;
      assert.equal(data.total_count, expected, 'Check results changed during pagination');
      assert.ok(Array.isArray(data[key]) && data[key].length <= 100);
      rows.push(...data[key]);
      if (rows.length === expected) return rows;
      assert.ok(data[key].length === 100 && rows.length < expected, 'Incomplete check pagination');
    }
    throw new Error('Check pagination exceeded its bound');
  };
  if (environment) {
    const settings = await request('/repos/' + repository + '/environments/release-preparation');
    assert.ok(
      Array.isArray(settings.protection_rules) &&
        settings.protection_rules.some(
          (rule) =>
            rule.type === 'required_reviewers' &&
            Array.isArray(rule.reviewers) &&
            rule.reviewers.length > 0,
        ),
      'The release-preparation environment requires explicit reviewer approval',
    );
  }
  const evidence = [];
  for (const workflow of workflows) {
    const runs = await list(
      '/repos/' +
        repository +
        '/actions/workflows/' +
        workflow +
        '/runs?branch=main&head_sha=' +
        commit,
      'workflow_runs',
    );
    assert.ok(runs.length > 0, 'A required workflow has no result: ' + workflow);
    for (const run of runs) {
      assert.equal(run.head_sha, commit, 'Workflow commit mismatch');
      assert.equal(run.head_branch, 'main', 'Workflow must run on main');
      assert.equal(run.path, '.github/workflows/' + workflow, 'Workflow path mismatch');
      assert.ok(['push', 'schedule', 'workflow_dispatch'].includes(run.event));
      assert.ok(
        Number.isSafeInteger(run.id) &&
          run.id > 0 &&
          Number.isSafeInteger(run.run_attempt) &&
          run.run_attempt > 0,
      );
      assert.ok(Number.isSafeInteger(run.run_number) && run.run_number > 0);
    }
    runs.sort((a, b) => b.run_number - a.run_number || b.run_attempt - a.run_attempt);
    const latest = runs[0];
    assert.equal(latest.status, 'completed', 'A required workflow is still pending: ' + workflow);
    assert.equal(latest.conclusion, 'success', 'The latest required workflow failed: ' + workflow);
    const jobs = await list(
      '/repos/' +
        repository +
        '/actions/runs/' +
        latest.id +
        '/attempts/' +
        latest.run_attempt +
        '/jobs',
      'jobs',
    );
    assert.ok(jobs.length > 0, 'A required workflow has no jobs');
    assert.equal(new Set(jobs.map((job) => job.id)).size, jobs.length, 'Duplicate job evidence');
    for (const job of jobs) {
      assert.equal(job.head_sha, commit, 'Job commit mismatch');
      assert.equal(job.status, 'completed', 'A required job is pending');
      assert.equal(job.conclusion, 'success', 'A required job failed or was skipped');
    }
    evidence.push({ workflow, runId: latest.id, attempt: latest.run_attempt, jobs: jobs.length });
  }
  return evidence;
}

async function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const tag = verifyReleaseTag({
    root,
    tag: process.env.RELEASE_TAG,
    publicKey: process.env.RELEASE_PUBLIC_KEY,
    fingerprint: process.env.RELEASE_KEY_FINGERPRINT,
    expectedCommit: process.env.EXPECTED_RELEASE_COMMIT,
  });
  const token = process.env.GITHUB_TOKEN;
  assert.ok(typeof token === 'string' && token.length > 0, 'Read-only workflow access is required');
  const checks = await verifyReleaseChecks({
    repository: process.env.GITHUB_REPOSITORY,
    commit: tag.commit,
    environment: true,
    request: async (path) => {
      const response = await globalThis.fetch('https://api.github.com' + path, {
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
        headers: {
          authorization: 'Bearer ' + token,
          accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      });
      assert.equal(response.status, 200, 'Required workflow evidence is unavailable');
      return response.json();
    },
  });
  assert.ok(process.env.GITHUB_OUTPUT, 'The workflow output file is required');
  appendFileSync(process.env.GITHUB_OUTPUT, 'commit=' + tag.commit + '\n');
  console.log(
    JSON.stringify({
      ...tag,
      checks,
      performanceAcceptance:
        'Separate calibrated campaigns and owner-deferred gates remain required',
    }),
  );
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
