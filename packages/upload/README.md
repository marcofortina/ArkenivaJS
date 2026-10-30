<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Streaming multipart uploads

`@arkenivajs/upload` registers bounded POST/PUT routes on the existing `@arkenivajs/api` Fastify listener. It delegates multipart syntax, MIME boundaries and native file backpressure to `@fastify/multipart` 10.1.6. Importing the package opens no listener and stores no file. The same routes support HTTP, verified direct HTTPS and secure HTTP/2.

The pinned workspace declares the SDK's missing Ajv 8 dependency through `packageExtensions`; its public declarations require that type even though upstream lists Ajv only as a development dependency. Independent packed-consumer verification preserves this exact extension. This prevents unrelated dependencies from selecting Ajv 6 for those declarations without changing multipart runtime code or disabling library type checks.

```typescript
import { uploadPlugin } from '@arkenivajs/upload';

const uploads = uploadPlugin({
  routes: [
    {
      path: '/uploads',
      method: 'POST',
      auth: { required: true, scopes: ['documents:write'] },
      policy: {
        maxRequestBytes: 6_000_000,
        maxFileBytes: 5_000_000,
        maxFiles: 2,
        maxFields: 4,
        maxFieldBytes: 1024,
        maxParts: 6,
        allowedMediaTypes: ['application/pdf'],
      },
      responseSchema: {
        type: 'object',
        required: ['files', 'bytes'],
        properties: { files: { type: 'integer' }, bytes: { type: 'integer' } },
        additionalProperties: false,
      },
      async handler(request) {
        let files = 0;
        let bytes = 0;
        for await (const part of request.parts) {
          if (part.kind === 'field') continue;
          files++;
          for await (const chunk of part.stream) bytes += chunk.byteLength;
        }
        return { files, bytes };
      },
    },
  ],
});
```

Register `uploads` alongside `apiPlugin`, `loggingPlugin` and the configured `securityPlugin` before `app.start()`. The API plugin must explicitly declare its authentication dependency, for example `apiPlugin({dependencies:['security']})`. The upload plugin resolves the authentication owner through its scoped support dependency. Missing authentication fails startup for protected routes. Every protected request verifies its bearer token, required scopes and tenant provenance before parsing its file. Neither headers nor form fields establish identity. Applications still enforce resource ownership when persisting data.

Omitted runtime authentication settings default to `required:true`. An intentionally public route requires `{required:false,reason:'...'}` with an application security-review reason; omitting a reason is invalid. Protected routes remain the recommended configuration.

## Stream ownership

`UploadRequest.context` contains the verified tenant, native cancellation signal, request ID, headers, query and parameters. Its ordinary JSON `body` is undefined. `parts` preserves field/file order and is single-pass. A file exposes `fieldName`, display-only `filename`, unverified `declaredMediaType`, `stream` and `discard(options?)`. Consume its entire stream or explicitly `await part.discard()` before advancing. A second consumer, early iterator return, ignored error or partially consumed request cannot receive a successful receipt. Discard can tighten the request deadline or add cancellation; zero and null options are invalid.

The handler's returned object must satisfy `responseSchema`. Acceptance means the handler finished, all parts were consumed and the response passed validation; it makes no durability promise about application storage. No automatic retry, buffering helper, temporary upload file, antivirus, signature detection or extraction is provided. The application owns storage, scanning, retention and external side-effect recovery after an interrupted request.

Filenames are normalized to NFC and rejected for path separators, drive syntax, control characters and dot paths. They remain untrusted display metadata. Do not derive storage keys from them. The declared MIME allowlist does not prove that a PDF or other document matches its claimed type.

## Bounds and lifecycle

All limits are positive safe integers. Request/file ceilings are 64 MiB; field values are at most 64 KiB, each file/field count at most 256 and total parts at most 512. A route needs an explicit nonempty MIME allowlist, up to 64 media types. At most 64 startup routes are accepted. Schema validation is bounded to depth 32, 4096 nodes and 64 KiB. Header/name bounds are finite and parser streams use 16 KiB high-water marks; Node may deliver a larger individual network chunk.

The wire guard counts actual multipart body chunks, including boundaries and metadata, before the native parser. It does not trust Content-Length or count HTTP headers, chunk-transfer framing or TLS overhead. An oversize native chunk is counted as observed input but cannot be acknowledged or exposed as a successful file chunk. No unbounded drain follows rejection.

Admission is 32 active requests per application, with no waiting queue. The shared request deadline uses `http.requestTimeoutMs`, default 30 seconds. Disconnect, timeout and shutdown cancel native streams. Logical cancellation retains its reservation until owned handler promises and file streams actually settle. JavaScript cannot preempt an application handler that ignores cancellation; shutdown reports failure at the core deadline rather than claiming that work stopped. Independent applications have independent streams, counters and lifecycle ownership.

## Results, errors and observations

Resolve `UPLOAD_CAPABILITY` as `UploadService`; `stats()` returns an immutable snapshot with active, received, successful and rejected request counts plus observed body bytes. Aborted requests count as rejected. No late route-registration API is exposed; collisions fail before bind.

Limits return `EK_UPLOAD_LIMIT`/413, unsupported declared MIME returns `EK_UPLOAD_MEDIA_TYPE`/415, malformed/incomplete input returns `EK_UPLOAD_STREAM` or `EK_UPLOAD_TRUNCATED`/400, deadlines return `EK_TIMEOUT`/408 and unavailable capacity returns `EK_BACKEND_UNAVAILABLE`/503. Authentication failures retain 401/403 behavior. Messages exclude client metadata and payloads. A rejected response cannot undo external writes already performed by an application handler.

Optional Pino and OTel signals report aggregate bytes, files, parts, request counts, outcome and elapsed time, using only bounded method/outcome labels. `upload.requests` counts each completed admitted request once; `upload.parts` counts native parts encountered, including a rejected part. `upload.aborted.requests` is the failed-request subset with cancellation, deadline or incomplete/truncated-stream errors. It is not an additional request or a count of exclusively client-initiated disconnects. Success/failure counters keep the existing `ok`/`error` labels. Rejection before physical admission is retained in service statistics but has no measured stream completion. Configure the metering plugin's `usageDefinitions` with `{'upload.request.bytes':'bytes','upload.files':'items','upload.parts':'items'}`. An installed enabled metering provider records the same observed byte/file/part quantities under the verified tenant and request ID, with one `http.requests` operation. No token, filename, field value or file content enters these signals. Missing custom usage definitions produce an observation gap and still close the metering session; they cannot change request success. Technical measurements do not compute monetary costs. Large-file heap and comparative performance acceptance remain separate from functional protocol tests.

See [the executable consumer](../../examples/upload/README.md). The suite exercises actual HTTP/HTTPS/HTTP2, signed OIDC, hostile metadata, body/file/field/count limits, partial consumption, disconnects, private capacity retention and graceful shutdown on Node 22/24/26. Performance campaigns and current-head remote release acceptance must pass before a production-ready release claim.
