// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { parse, stringify } from 'yaml';
import { verifyReleaseChecks, verifyReleaseTag } from '../release-prepare.mjs';
import { validateWorkflow } from '../workflow-policy.mjs';

const commit = 'a'.repeat(40);
const names = ['ci.yml', 'security.yml', 'compatibility.yml', 'performance.yml'];
function apiFixture(mutate = () => undefined, jobCount = 2) {
  const calls = [];
  return {
    calls,
    request: async (path) => {
      calls.push(path);
      if (path.endsWith('/environments/release-preparation')) {
        const value = {
          protection_rules: [
            {
              type: 'required_reviewers',
              prevent_self_review: true,
              reviewers: [{ type: 'Team', reviewer: { id: 42 } }],
            },
          ],
        };
        mutate(value, 'environment');
        return value;
      }
      const page = Number(new URL('https://fixture.invalid' + path).searchParams.get('page'));
      const name = names.find((name) => path.includes('/workflows/' + name + '/'));
      if (name) {
        const row = {
          id: names.indexOf(name) + 1,
          run_number: 2,
          run_attempt: 1,
          path: '.github/workflows/' + name,
          head_sha: commit,
          head_branch: 'main',
          event: 'push',
          status: 'completed',
          conclusion: 'success',
        };
        const value = { total_count: 1, workflow_runs: [row] };
        mutate(value, 'runs', name);
        return value;
      }
      const jobs = Array.from({ length: jobCount }, (_, id) => ({
        id: id + 1,
        head_sha: commit,
        status: 'completed',
        conclusion: 'success',
      }));
      const value = { total_count: jobCount, jobs: jobs.slice((page - 1) * 100, page * 100) };
      mutate(value, 'jobs');
      return value;
    },
  };
}
const verify = (fixture, environment = true) =>
  verifyReleaseChecks({
    repository: 'fixture/project',
    commit,
    request: fixture.request,
    environment,
  });

test('Release checks require every exact workflow attempt and every paginated job', async () => {
  const api = apiFixture(() => undefined, 101);
  const result = await verify(api);
  assert.deepEqual(
    result.map((row) => row.jobs),
    [101, 101, 101, 101],
  );
  assert.equal(api.calls.filter((path) => path.includes('/jobs?')).length, 8);
  assert.ok(api.calls.every((path) => !path.includes('POST')));
  await assert.doesNotReject(
    verify(
      apiFixture((value, type) => {
        if (type === 'environment') value.protection_rules[0].prevent_self_review = false;
      }),
    ),
  );
});

test('Release checks refuse missing, pending, failed, skipped, foreign or incomplete evidence', async () => {
  const changes = [
    (value, type) => {
      if (type === 'runs') {
        value.total_count = 0;
        value.workflow_runs = [];
      }
    },
    (value, type) => {
      if (type === 'runs') value.workflow_runs[0].status = 'in_progress';
    },
    (value, type) => {
      if (type === 'runs') value.workflow_runs[0].conclusion = 'failure';
    },
    (value, type) => {
      if (type === 'runs') value.workflow_runs[0].head_sha = 'b'.repeat(40);
    },
    (value, type) => {
      if (type === 'runs') value.workflow_runs[0].head_branch = 'foreign';
    },
    (value, type) => {
      if (type === 'runs') value.workflow_runs[0].path = '.github/workflows/foreign.yml';
    },
    (value, type) => {
      if (type === 'jobs') value.jobs[0].conclusion = 'skipped';
    },
    (value, type) => {
      if (type === 'jobs') value.jobs[0].head_sha = 'b'.repeat(40);
    },
    (value, type) => {
      if (type === 'jobs') value.jobs[0].status = 'queued';
    },
    (value, type) => {
      if (type === 'jobs') value.total_count = 101;
    },
    (value, type) => {
      if (type === 'jobs') value.jobs[1].id = value.jobs[0].id;
    },
    (value, type) => {
      if (type === 'environment') value.protection_rules = [];
    },
    (value, type) => {
      if (type === 'environment') value.protection_rules[0].reviewers = [];
    },
  ];
  for (const change of changes) await assert.rejects(verify(apiFixture(change)));
  await assert.rejects(
    verify({
      request: async () => {
        throw new Error('Unavailable');
      },
    }),
    /Unavailable/,
  );
});

test('A newer failed or pending attempt cannot reuse an older successful run', async () => {
  for (const status of ['in_progress', 'completed']) {
    const api = apiFixture((value, type) => {
      if (type !== 'runs') return;
      const old = { ...value.workflow_runs[0], run_number: 1 };
      value.workflow_runs[0].status = status;
      value.workflow_runs[0].conclusion = status === 'completed' ? 'failure' : null;
      value.workflow_runs.unshift(old);
      value.total_count = 2;
    });
    await assert.rejects(verify(api));
  }
});

test('Release tag verification uses an isolated owner key and rejects forged tag and ancestry inputs', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'arkenivajs-release-test-'));
  const signing = join(root, 'signing'),
    repository = join(root, 'repository');
  mkdirSync(signing, { mode: 0o700 });
  mkdirSync(repository);
  const env = {
    ...process.env,
    GNUPGHOME: signing,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
  };
  const command = (program, args, extra = {}) =>
    execFileSync(program, args, {
      cwd: repository,
      env,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 15000,
      ...extra,
    }).trim();
  const git = (...args) => command('git', args);
  try {
    command('gpg', [
      '--batch',
      '--pinentry-mode',
      'loopback',
      '--passphrase',
      '',
      '--quick-generate-key',
      'Release fixture <release@fixture.invalid>',
      'ed25519',
      'sign',
      '1d',
    ]);
    const fingerprint = command('gpg', ['--batch', '--with-colons', '--list-keys'])
      .split('\n')
      .find((line) => line.startsWith('fpr:'))
      .split(':')[9];
    const publicKey = command('gpg', ['--batch', '--armor', '--export', fingerprint]);
    git('init', '-b', 'main');
    git('config', 'user.name', 'Release fixture');
    git('config', 'user.email', 'release@fixture.invalid');
    git('config', 'user.signingkey', fingerprint);
    mkdirSync(join(repository, 'packages'));
    mkdirSync(join(repository, 'packages', 'fixture'));
    const manifest = JSON.stringify({ name: 'fixture', version: '0.1.0', private: true }) + '\n';
    writeFileSync(join(repository, 'package.json'), manifest);
    writeFileSync(join(repository, 'packages', 'fixture', 'package.json'), manifest);
    git('add', '--all');
    git('commit', '-m', 'Create release fixture');
    const sha = git('rev-parse', 'HEAD');
    git('update-ref', 'refs/remotes/origin/main', sha);
    git('-c', 'gpg.format=openpgp', 'tag', '-s', 'v0.1.0', '-m', 'Release fixture');
    const options = { root: repository, tag: 'v0.1.0', fingerprint, publicKey };
    await t.test('The exact owner-signed tag is accepted without authorizing publication', () => {
      assert.deepEqual(verifyReleaseTag(options), {
        tag: 'v0.1.0',
        version: '0.1.0',
        commit: sha,
        publicationAuthorized: false,
      });
      assert.equal(git('status', '--porcelain=v1'), '');
    });
    await t.test(
      'Post-build verification retains the exact signed candidate and checked-out source',
      () => {
        assert.equal(verifyReleaseTag({ ...options, expectedCommit: sha }).commit, sha);
        assert.throws(
          () => verifyReleaseTag({ ...options, expectedCommit: 'b'.repeat(40) }),
          /identity changed/,
        );
        git('checkout', '-b', 'descendant');
        git('commit', '--allow-empty', '-m', 'Create another clean checkout');
        try {
          assert.equal(verifyReleaseTag(options).commit, sha);
          assert.throws(
            () => verifyReleaseTag({ ...options, expectedCommit: sha }),
            /built source differs/,
          );
        } finally {
          git('checkout', 'main');
        }
      },
    );
    await t.test(
      'Inherited Git configuration and alternate repository paths cannot override verification',
      () => {
        const values = {
          GIT_DIR: '/nonexistent/release-repository',
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'gpg.program',
          GIT_CONFIG_VALUE_0: '/nonexistent/verification-program',
        };
        const before = Object.fromEntries(
          Object.keys(values).map((key) => [key, process.env[key]]),
        );
        Object.assign(process.env, values);
        try {
          assert.equal(verifyReleaseTag(options).commit, sha);
        } finally {
          for (const [key, value] of Object.entries(before)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
          }
        }
      },
    );
    await t.test(
      'Foreign public keys, private material, malformed versions and lightweight tags fail',
      () => {
        assert.throws(() => verifyReleaseTag({ ...options, fingerprint: 'F'.repeat(40) }));
        assert.throws(() =>
          verifyReleaseTag({ ...options, publicKey: '-----BEGIN PGP ' + 'PRIVATE KEY BLOCK-----' }),
        );
        assert.throws(() => verifyReleaseTag({ ...options, tag: 'v0.1.0\ncommit=forged' }));
        assert.throws(() => verifyReleaseTag({ ...options, tag: 'v0.1.0-01' }));
        git('tag', 'v0.2.0');
        assert.throws(() => verifyReleaseTag({ ...options, tag: 'v0.2.0' }));
      },
    );
    await t.test('An unsigned annotation and a signed mismatched version fail', () => {
      const signed = git('rev-parse', 'refs/tags/v0.1.0');
      git('tag', '-f', '-a', 'v0.1.0', '-m', 'Unsigned fixture');
      try {
        assert.throws(() => verifyReleaseTag(options));
      } finally {
        git('update-ref', 'refs/tags/v0.1.0', signed);
      }
      git('-c', 'gpg.format=openpgp', 'tag', '-s', 'v0.4.0', '-m', 'Mismatched release fixture');
      assert.throws(() => verifyReleaseTag({ ...options, tag: 'v0.4.0' }), /version disagree/);
    });
    await t.test('A copied signed annotation cannot masquerade as another version tag', () => {
      git('update-ref', 'refs/tags/v0.1.1', git('rev-parse', 'refs/tags/v0.1.0'));
      assert.throws(() => verifyReleaseTag({ ...options, tag: 'v0.1.1' }), /annotation/);
    });
    await t.test('An altered signed annotation fails cryptographic verification', () => {
      const original = git('rev-parse', 'refs/tags/v0.1.0');
      const data =
        git('cat-file', 'tag', original).replace('Release fixture\n', 'Altered release fixture\n') +
        '\n';
      const altered = command('git', ['hash-object', '-t', 'tag', '-w', '--stdin'], {
        input: data,
      });
      git('update-ref', 'refs/tags/v0.1.0', altered);
      try {
        assert.throws(() => verifyReleaseTag(options));
      } finally {
        git('update-ref', 'refs/tags/v0.1.0', original);
      }
    });
    await t.test('A signed commit outside main and a dirty source checkout fail closed', () => {
      git('checkout', '--orphan', 'foreign');
      git('add', '--all');
      git('commit', '-m', 'Create unrelated history');
      git('update-ref', 'refs/remotes/origin/main', git('rev-parse', 'HEAD'));
      assert.throws(() => verifyReleaseTag(options));
      git('update-ref', 'refs/remotes/origin/main', sha);
      git('checkout', 'main');
      writeFileSync(join(repository, 'unexpected.txt'), 'dirty\n');
      assert.throws(() => verifyReleaseTag(options), /clean/);
    });
  } finally {
    execFileSync('gpgconf', ['--homedir', signing, '--kill', 'gpg-agent'], { stdio: 'ignore' });
    rmSync(root, { recursive: true, force: true });
  }
});

test('Release workflow permits only explicit main preparation without publication credentials', () => {
  const text = readFileSync(
    new URL('../../.github/workflows/release.yml', import.meta.url),
    'utf8',
  );
  assert.deepEqual(validateWorkflow('release.yml', text), { jobs: 1, actions: 3 });
  assert.doesNotMatch(text, /npm publish|id-token|contents: write|attestations: write/);
  for (const change of [
    (value) => {
      value.on.push = { branches: ['main'] };
    },
    (value) => {
      value.concurrency['cancel-in-progress'] = true;
    },
    (value) => {
      delete value.jobs.prepare.environment;
    },
    (value) => {
      value.jobs.prepare.permissions['id-token'] = 'write';
    },
  ]) {
    const value = parse(text);
    change(value);
    assert.throws(() => validateWorkflow('release.yml', stringify(value)));
  }
});
