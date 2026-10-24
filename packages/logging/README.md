# @arkenivajs/logging

Pino JSON logging through the typed Logger interface. `createLogger({service, level?, destination?, bufferLimitBytes?, redactPaths?, redactValues?, onDiagnostic?})` returns a managed logger. Level defaults to info; the destination defaults to standard output. The pending-write budget defaults to one MiB. `loggingPlugin(options?)` installs one logger per application and closes it during shutdown.

`trace`, `debug`, `info`, `warn`, `error` and `fatal` attempt synchronous emission; `flush({signal?, timeoutMs?})` waits for destination write callbacks, with a default 30,000 ms deadline. Acknowledged writes do not imply disk fsync or downstream durability. Saturated or failed transports drop further messages, expose immutable `stats()` counters and emit one sanitized diagnostic. A failed flush rejects with `EK_TIMEOUT`, `EK_ABORTED` or `EK_BACKEND_UNAVAILABLE`. Invalid fields and levels use `EK_CONFIG_INVALID`; emissions after close use `EK_RESOURCE_CLOSED`.

`child(fields)` snapshots context and uses Pino child loggers. Existing service and trace/request correlation fields cannot be overridden. `setLevel` validates the exact LogLevel union, including silent. `run(fields, callback)` scopes diagnostic context with AsyncLocalStorage across asynchronous work. Context does not prove identity or tenant authorization. Children share the root destination and lifetime.

Known credential keys are redacted at every traversed level, custom paths use Pino redaction and exact additional secret values can be supplied explicitly. Errors use safe envelopes, cycles receive a safe marker and accessors are not invoked. Serialization has depth, field and string bounds; severity and timestamp fields cannot be spoofed. Never embed unknown confidential data into free-form messages.

`close(options?)` is idempotent, flushes and stops the context collector. Set `ownDestination:true` only for a stream whose lifecycle belongs to this logger; otherwise the caller owns it. A transport that ignores callbacks may finish after a timed-out flush. Counters report observed attempts, dropped lines and failed write acknowledgements rather than assuming delivery.

A complete local usage sequence is:

```ts
import { createLogger } from '@arkenivajs/logging';

const log = createLogger({
  service: { name: 'orders', version: '1.0.0', environment: 'development' },
});
await log.run({ requestId: 'example-request' }, async () => {
  log.info('operation completed', { password: 'fake-private-value' });
});
await log.close();
```

The JSON line includes the service, request id, timestamp and info severity; the password field contains `[REDACTED]`. `pnpm smoke` exercises the same flow against a captured writable stream and checks the actual JSON output.
