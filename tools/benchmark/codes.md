# Native barcode functional comparison

Build the workspace and select a fresh absolute output directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation codes --verify /private/codes-verification
```

Four sequential isolated Node profiles exercise bare qrcode/bwip/Sharp/ZXing,
the public barcode plugin and the actual standard/detailed diagnostic SDK modes.
Each roundtrips real PNG images for QR, CODE128 and EAN13 and generates QR SVG.
The tests additionally decode each encoder's images with the other service and
check that image input bytes remain unchanged. Different valid raster sizes,
PNG encodings or SVG serialization are not required to be byte-identical.

The tool accepts only `--verify`. Reports use `measured: false`, null resource
results, no timing samples and `releaseGate: false`. `--smoke` fails before
workers or output directories start: process CPU/RSS from the parent alone
would omit the framework's owned native codec child processes. A complete
process-tree accounting implementation is required before sampling is enabled.
No timing or resource acceptance is inferred from functional parity.

Generation and detection use the mature pinned backends: qrcode 1.5.4, bwip-js
4.11.4, Sharp 0.35.5 and ZXing 0.21.3. The baseline accepts a fixed valid corpus,
without claiming equivalent deployment validation or adversarial image safety.
The framework retains its byte/pixel limits, bounded admission, owned process
isolation and lifecycle. No decoder algorithm is implemented by the tool.

Actual standard/detailed metrics reach the owned collector; symbol contents
must not appear in telemetry or the report. SDK drop/export checks remain
active. No throughput, process-tree resource, release budget, repeated campaign
or one-hour soak evidence is claimed.
