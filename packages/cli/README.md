# @arkenivajs/cli

The explicit dependency catalog covers all 60 application runtime modules,
including GraphQL, tenant routing, federation profiles, document codecs and
native protocol adapters. The CLI itself is excluded. Addition edits only the
manifest; each selected capability still requires explicit application setup.

Create a small ESM HTTP service or add one explicit framework dependency. The CLI uses Node's argument parser and filesystem primitives, with `jsonc-parser` for strict manifest inspection and localized edits. It does not install dependencies, run package scripts, initialize Git, contact registries or publish packages.

```sh
arkenivajs new hello-service
cd hello-service
arkenivajs add dns
pnpm install
pnpm build
pnpm start
```

Run the installation commands only after the exact declared framework packages have been published through the approved release process, or after deliberately configuring equivalent local packed artifacts. The current source workspace remains private; CLI availability does not imply registry availability.

The starter registers `loggingPlugin()` and `apiPlugin()` explicitly, listens on `127.0.0.1:8080`, and exposes the public development greeting `/hello`. It includes strict TypeScript settings, the full AGPL license, SPDX/copyright notices and a `.gitignore` containing `*.patch`. It adds only core, logging and inbound API dependencies. Deployment authentication, TLS or trusted ingress and application-specific policy require deliberate configuration.

`arkenivajs add dns` and `arkenivajs add @arkenivajs/dns` edit only `dependencies` in `package.json`. Import and configure the selected module's documented plugin yourself; dependencies are never activated implicitly. The command leaves source files and existing lockfiles untouched. Run your package manager afterward to update the lockfile. Unimplemented module names are rejected, and the CLI itself cannot be added as an application runtime module.

The default new-project framework version matches the CLI version. `--framework-version 1.2.3` selects an exact release. Addition otherwise uses the existing exact `@arkenivajs/core` dependency. Ranges, local paths and version conflicts are rejected, including conflicting entries in development, optional or peer dependencies. An already matching runtime dependency is a byte-for-byte no-op.

## Filesystem behavior

Use an existing, trusted, quiescent working directory. Ancestor symlinks are rejected. Project names are bounded lowercase names, not paths. Existing project directories, files and symlinks are never overwritten, even when a directory is empty. New directories have mode `0700` and new files `0600`.

A cooperative exclusive lock admits one writer; contention fails immediately without an unbounded queue. The CLI never deletes a foreign lock or automatically breaks a stale one. After an interrupted process, inspect the project and verify that no writer remains before removing its stale lock. A manifest must be a single regular file, not a symlink, directory or hardlink, with at most 1 MiB of valid UTF-8 JSON, 10,000 syntax-tree nodes and depth 32. Duplicate/prototype keys, comments and trailing commas are rejected.

Manifest edits use a flushed same-directory temporary file and atomic rename, preserving unrelated text, line endings and file permissions. The original inode, modification time and size are rechecked before replacement. This cooperative protocol is not a security boundary against a hostile process concurrently replacing workspace paths. Do not run external editors or installers against the same manifest during an edit.

Creation is a sequence of exclusive writes. An I/O failure, timeout or cancellation after a write may leave an incomplete directory; there is no claim of transactional rollback and no recursive cleanup of user project directories. Inspect any partial output before retrying. Cancellation retains the cooperative lock until outstanding native work actually settles; after a process kill, the stale-lock rule applies.

## Programmatic API and errors

```typescript
import { newProject, addModule } from '@arkenivajs/cli';

const project = await newProject('hello-service', { cwd: '/owned/projects', timeoutMs: 5000 });
await addModule('dns', { cwd: project.directory });
```

Both functions return an immutable `{directory, changed, files}` receipt. `ProjectOptions` accepts `cwd`, an exact `frameworkVersion`, `signal` and `timeoutMs` (integer 1–30,000; default 5,000 ms). Null, unknown fields and accessors are rejected. Timeout/cancellation reject the public waiter; native filesystem operations cannot always be interrupted, so their private task remains observed and stops at the next safe boundary. A racing write is explicitly reported with `details.outcome = 'unknown'`.

Invalid configuration or manifest conflicts use `EK_CONFIG_INVALID`; unavailable files/locks and filesystem failures use `EK_BACKEND_UNAVAILABLE`; cancellation and deadlines use `EK_ABORTED` and `EK_TIMEOUT`. Diagnostics do not echo file contents, arbitrary arguments or native filesystem paths. The executable prints safe errors to stderr and returns a nonzero exit status. `--help` and `--version` perform no project mutation.

See the [runnable consumer](../../examples/cli/README.md) for compilation and actual HTTP verification against installed artifacts. Release/performance gates remain separate from these local functional checks.
