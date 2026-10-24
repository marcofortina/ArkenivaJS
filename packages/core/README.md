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
