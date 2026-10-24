# @arkenivajs/core

Typed foundations for modular ESM applications. `KitError` preserves the developer message and original `cause` internally. Call `toSafeJSON()` at external boundaries; it returns a stable error code and a fixed safe message. JSON serialization uses the same safe envelope. Stack traces, raw messages and details never enter that envelope.

```ts
import { KitError } from '@arkenivajs/core';

const error = new KitError({
  code: 'EK_TIMEOUT',
  message: 'The internal operation exceeded its deadline',
  retryable: false,
});
const response = error.toSafeJSON();
```

`retryable` defaults to false and never authorizes automatic replay. Error details are immutable primitive metadata. Native causes may contain sensitive data and must remain within trusted components.

The documented `@arkenivajs/core/support` integration entry point provides `ConfigStore`, `compileSchema`, `copyData`, `freezeData`, `mergeData`, `redactData` and `within`. These primitives let adapters share one validated data model and error identity without circular package dependencies. They perform no I/O at import.

`ConfigStore<T>(initial, {schema, dynamicPaths?, secretPaths?, preflight?})` validates strict JSON Schema without coercion. Getters and snapshots are deeply immutable; snapshots redact known secret names and explicit secret paths. `reload` merges, validates and preflights a new generation before one atomic swap. Failed reloads retain the previous generation and reject with `EK_CONFIG_RELOAD_REJECTED`. Preflight functions must be side-effect-free. Static data, credentials and security policy require reconstruction.

`within(work, {signal?, timeoutMs?})` bounds a promise with `EK_ABORTED` or `EK_TIMEOUT`; timeout defaults to 30,000 ms and must be a positive integer. It removes its listener and timer on every outcome. The work callback must cooperate with cancellation to terminate its own resources.
