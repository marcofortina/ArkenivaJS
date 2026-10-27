<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Bounded native PDF documents

`@arkenivajs/documents-pdf` composes `pdf-lib@1.17.1`, `pdfjs-dist@6.4.299` and the native fontkit adapter. Register `documentsPdfPlugin({defaults,fontAllowlist,policy})`, start the application and resolve `PDF_CAPABILITY` as `PdfService`. Public types expose document values, not native engine objects. Imports and factories perform no document, filesystem, process or network operations.

```ts
const pdf = app.resolve<PdfService>(PDF_CAPABILITY);
const builder = pdf.create();
builder.addText('Protocol 12345/2026', 1, 40, 40, {
  font: 'Helvetica',
  size: 12,
  colorHex: '#000000',
});
const bytes = await builder.save();
const info = await pdf.inspect(bytes);
const pages = await pdf.extractText(bytes);
```

The [executable consumer](../../examples/pdf/README.md) creates searchable text, adds rotated text, merges two pages and verifies actual Pino/OTel diagnostic privacy.

## Five explicit operations

`create(limits?)` returns a bounded builder. `addText(text,page,x,y,{font,size,colorHex})` snapshots validated values synchronously. Pages are one-based and created implicitly up to the highest selected page, using A4 portrait dimensions in PDF points. Saving an empty builder produces one blank page. `save(operation?)` returns a complete Uint8Array; saves may be repeated sequentially. Concurrent saves or changes during saving fail explicitly.

`inspect(bytes, limitsAndOperation?)` returns `{pages,encrypted,signed,title?,author?}`. Metadata controls are removed; oversized metadata fails instead of entering diagnostics. The signature flag means native signature structures are present, including certification/timestamp structures and unsigned signature fields conservatively treated as protected. It does not verify cryptographic validity, certificate trust or legal signature status. Encrypted inputs are rejected without a password option; successful inspection reports `encrypted:false`.

`extractText(bytes, options?)` returns one `{page,items}` per page. Each item contains native text, x/y coordinates, width and height. Extraction is best effort from searchable content, without OCR or a guaranteed reading order for arbitrary layouts. Existing page rotation is preserved; coordinates follow the native PDF text transform in PDF points. Native text chunks are consumed with backpressure and bounded item/output growth.

`merge(inputs, options?)` copies native pages in input order. `addText(bytes,spec,options?)` adds searchable text to an existing page; `spec` requires page, text, x/y, font, size and color, with optional rotationDegrees normalized modulo 360. Coordinates use the native unrotated page space, with origin at the bottom left. Neither operation promises preservation of every proprietary PDF feature.

Both rewriting operations independently reject signature structures with `EK_PDF_SIGNED`, without trusting an earlier caller inspection. Source bytes are copied before asynchronous work, preventing a caller mutation from bypassing checks. Active JavaScript/actions, XFA, embedded-file collections and other identified active structures are rejected for rewriting; read-only inspection/extraction never executes document actions. Native object graphs and indirect references are inspected; signature-looking strings in ordinary metadata are not treated as signatures. Ambiguous escaped-name forms that the pinned parser cannot faithfully classify fail parsing rather than weakening signature policy.

## Fonts and text

The font allowlist is required and nonempty. Entries are exact standard PDF font names, such as Helvetica, or absolute deployment-controlled font file paths. Request values can select only those exact entries. No URL fetching, font discovery or implicit system-font fallback occurs. Standard fonts support their native encodings; use a suitable embedded Unicode font for other scripts.

Custom fonts are read through bounded, no-follow, nonblocking regular-file handles. Group/world-writable files and leaf symlinks are refused; changes during reading fail. Copy deployment assets into appropriately protected regular files rather than passing a writable package-store file directly. At most 4 MiB per font and 16 MiB total font data per operation is accepted. The child owns native font parsing and embedding; parent-owned temporary copies are erased after physical completion.

The functional font profile includes standard fonts and embedded WOFF/TrueType-compatible fonts with searchable Greek and Hebrew RTL text. The upstream fontkit WOFF2 composite-glyph path is not a supported profile; failed native embedding is reported without silently substituting another font. Unsupported glyphs fail rather than producing a successful replacement-glyph document. Text shaping and extraction follow the pinned native engines, without a custom font, bidi or PDF parser. Coordinates are finite within ±1000000 points, font size is 0.01–1000 points, colors are `#RRGGBB`, and text segments are bounded by 1 MiB and the selected document byte budget.

## Limits and process ownership

Defaults are maxBytes 16 MiB (maximum 128 MiB), maxPages 100 (maximum 1000), maxTextItems 100000 (maximum 1000000) and maxDecodeMs 5000 (maximum 120000). Policy requires maxConcurrent 1–4 and timeoutMs 1–120000; input/output byte limits default to 16 MiB, maximum 128 MiB. Limits are positive integers. Per-call deadlines cannot exceed either the configured timeout or decode budget. Input merge lists have at most 128 documents with a shared compressed/input byte budget. Output and source snapshots remain finite; this public API returns complete byte arrays and does not expose unlimited byte streams.

Each asynchronous operation admits one owned child without a queue. Builders retain only bounded text specifications; native work starts on save. Every operation uses the selected Node executable and a whitelisted environment, without application secrets, NODE_OPTIONS or NODE_DEBUG. JavaScript filesystem reads are restricted to module roots. PDF.js's bundled Node-API canvas support requires native-addon permission for its standard DOM primitives; that permission does not contain native addon code. No application-global canvas shims are installed.

The verified deployment profile is Linux with `/usr/bin/prlimit` from util-linux. The wrapper sets a 1 GiB hard data-allocation limit and disables core dumps before exec, leaving the parent limits unchanged. V8 old space is limited to 512 MiB. An independent parent monitor samples Linux RSS every 10 ms and terminates work above `min(512 MiB,256 MiB+2*maxBytes)`. RSS sampling may briefly exceed its threshold; the kernel data limit is not a total RSS limit and includes V8 code reservations. This is resource-bounded process isolation, not an OS security sandbox. Missing/unsafe limiter support fails closed; no quieter unbounded fallback is provided.

Abort/deadlines terminate the owned process. Resource admission is retained until actual child exit and any font reads settle. Successful output is acknowledged after native cleanup and physical exit. Application drain cancels and joins active operations. Calls require READY and fail after shutdown. No default temporary files or persistent storage are used. Pinned native binary-data loading accepts only filenames actually shipped in PDF.js's local CMap/font directories, with finite resource bounds; input cannot choose remote URLs or arbitrary local resource paths.

`EK_PDF_PARSE`, `EK_PDF_SIGNED`, `EK_PDF_LIMIT` and common configuration/lifecycle/deadline errors use generic messages without raw parser causes, paths, document text or metadata. Optional Pino/OTel adapters record fixed operation/outcome, actual input/output bytes, native CPU/duration, pages per second and sampled native RSS high-water measurements. Memory samples do not claim continuous peak measurement. The module never evaluates PDF JavaScript or starts OCR/rendering jobs.

PDF.js is Apache-2.0 licensed; pdf-lib, fontkit and native canvas are MIT licensed. Unicode test fonts are separately licensed OFL-1.1 development dependencies. PDFKit is a test-only independent producer of real AES-encrypted fixtures. A metadata-only patch declares the test producer’s PNG dependency as MIT, matching its actual bundled [license notice](THIRD_PARTY_NOTICES.md); JavaScript remains unchanged. No native library source is patched. Comparative performance and release acceptance remain separate gates.
