<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# QR codes and barcodes

Register `dataCodesPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 5000 } })`,
start the application and resolve `CODES_CAPABILITY` as `CodeService`. Importing this
package creates no processes, connections or files. The [runnable example](../../examples/barcodes/README.md)
uses only public capability contracts.

`generateQr(text, options)` and `generateBarcode(text, 'QR' | 'CODE128' | 'EAN13', options)`
return PNG or UTF-8 SVG bytes. `decode(bytes, options)` accepts PNG/JPEG and returns
the first supported symbol detected by ZXing, or an empty list when a valid raster
contains no detected symbol. This adapter does not scan multiple symbols or promise
detection of every orientation, damaged carrier or image. Native confidence is
unavailable and is omitted. Contents, including URLs, remain untrusted data and are
never fetched or used to authenticate anyone. No DOM or browser adapter is loaded.

qrcode 1.5.4 encodes QR, bwip-js 4.11.4 encodes 1D carriers and validates the complete
13-digit EAN13 check digit, @zxing/library 0.21.3 decodes the three explicit formats,
and sharp 0.35.5/libvips is the explicit PNG/JPEG-to-grayscale adapter. The ZXing
version supports Node 22; newer releases require Node 24. Upstream is in maintenance
mode. No carrier, checksum or raster algorithm is implemented by the framework.
Dependencies retain their upstream license and attribution files; sharp's packaged
libvips binaries carry their own LGPL notices. Native install/build hooks are disabled.

Each application starts 1–4 owned codec processes. Each process admits one job,
uses a 128 MiB V8 heap ceiling and one libvips thread, with libvips caching disabled.
The V8 ceiling is not an OS RSS guarantee. Native buffers are separately bounded by
pixels and byte limits. Applications must include the configured process count in
their deployment memory budget. Only fixed locale/timezone/runtime environment
values are inherited; application credentials and loader overrides are excluded.

There is no pending job queue or implicit retry. Saturation uses `EK_CODE_LIMIT`.
Decode accepts native `AbortSignal` and a positive `timeoutMs` that can tighten the
deployment deadline. Abort/deadline kills the owned process, retaining admission
until the OS reports process closure, then bootstraps one replacement. A failed
replacement makes the facade unavailable instead of retrying forever. Stopping the
application kills all owned processes and waits for closure, including native image
threads. Stopped facades use `EK_RESOURCE_CLOSED`.

Deployment defaults are PNG, width 512, 4,194,304 pixels, QR correction M,
1,048,576 input bytes and 8,388,608 output bytes. Explicit ceilings are width 4096,
16,777,216 pixels, 8,388,608 input bytes, 16,777,216 output bytes and 120,000 ms.
All numeric limits are positive safe integers. Options are snapshotted without
invoking getters; per-call width/pixels/deadline can only tighten deployment limits.
QR input is capped at 2953 UTF-8 bytes; actual capacity depends on the native mode
and correction level. CODE128 accepts at most 256 ASCII characters. EAN13 requires
exactly 13 ASCII digits. Invalid UTF-16 and empty carrier strings reject. Nothing is
silently truncated. Image input is copied; shared-memory images are rejected.

QR output has the requested square width and a four-module quiet zone. A width too
small for the native symbol rejects. 1D output uses the largest integer native bar
scale fitting `widthPixels`, preserving quiet zones; actual width may be smaller.
Header metadata is inspected before raster allocation. Pixel/byte limits apply to
both encoded images and decoded rasters; animated/multipage images are unsupported.
SVG is produced only by the trusted encoders and is never accepted as decode input.

Unsupported formats use `EK_CODE_UNSUPPORTED`, malformed inputs/native failures use
`EK_CODE_DECODE`, bounds use `EK_CODE_LIMIT` and cancellation/deadlines use the common
`EK_ABORTED`/`EK_TIMEOUT`. Native payload-bearing messages and abort reasons never
cross the facade. Timeout rejects late acknowledgements and cannot imply completed
work was undone. Code generation has no external persistence side effect.

Optional existing logger/telemetry plugins receive only bounded operation, symbology,
outcome, duration, output-byte and successful-image pixel metadata. Instruments are
`codes.duration.ms` (ms), `codes.output.bytes` (By), and `codes.image.pixels` ({pixel}).
Fixed labels are `codes.operation`, `codes.symbology`, `codes.outcome`. No contents,
image bytes, native errors or URLs are logged/exported. Observer failures cannot
change results or retry jobs. These counts are successful image dimensions and
encoded/decoded UTF-8 bytes, not process RSS, CPU or tenant allocation.

Native interoperability, lifecycle, security and contract tests accompany this
package. Performance campaigns and remote compatibility remain separate release gates.
