// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PDFDocument,
  PDFDict,
  PDFArray,
  PDFName,
  PDFRef,
  PDFRawStream,
  StandardFonts,
  rgb,
  degrees,
} from 'pdf-lib';
import type { PDFObject, PDFFont } from 'pdf-lib';
import fontkit from '@pdf-lib/fontkit';
import type { PdfInfo, PdfTextPage, PdfTextItem, PdfTextSpec } from './contracts.js';
import type { Limits } from './settings.js';
import { builtins } from './settings.js';
import { failure, integer } from './validation.js';

export interface Work {
  readonly operation: 'create' | 'inspect' | 'extract' | 'merge' | 'add';
  readonly limits: Limits;
  readonly maximum: number;
  readonly inputs: readonly Uint8Array[];
  readonly specs: readonly Readonly<Required<PdfTextSpec>>[];
  readonly fonts: Readonly<Record<string, Uint8Array>>;
}
interface NativeTextItem {
  readonly str?: string;
  readonly transform?: readonly number[];
  readonly width?: number;
  readonly height?: number;
}
interface NativePage {
  streamTextContent(options: {
    includeMarkedContent: false;
    disableNormalization: true;
  }): ReadableStream<{ items: readonly NativeTextItem[] }>;
  cleanup(): boolean;
}
interface NativeDocument {
  readonly numPages: number;
  getMetadata(): Promise<{
    info: {
      Title?: unknown;
      Author?: unknown;
      IsSignaturesPresent?: unknown;
      IsEncrypted?: unknown;
    };
  }>;
  getPage(page: number): Promise<NativePage>;
}
interface PdfEngine {
  getDocument(options: object): {
    readonly promise: Promise<NativeDocument>;
    destroy(): Promise<void>;
  };
}
const enginePath = import.meta.resolve('pdfjs-dist/legacy/build/pdf.mjs'),
  engine = (await import(enginePath)) as PdfEngine,
  engineRoot = dirname(dirname(dirname(fileURLToPath(enginePath))));
const bundleDirectories = new Map([
  ['cMapUrl', 'cmaps'],
  ['standardFontDataUrl', 'standard_fonts'],
]);
/** The native documented binary-data port can read only names actually shipped in approved library directories. */
class LocalBinaryData {
  async fetch(request: { kind: string; filename: string }): Promise<Uint8Array> {
    const folder = bundleDirectories.get(request.kind),
      name = request.filename;
    if (
      !folder ||
      typeof name !== 'string' ||
      basename(name) !== name ||
      !/^[A-Za-z0-9_.-]{1,160}$/.test(name)
    )
      throw failure();
    const root = join(engineRoot, folder),
      names = await readdir(root);
    if (!names.includes(name)) throw failure();
    const value = await readFile(join(root, name));
    if (value.length > 4 * 1024 * 1024) throw failure('EK_PDF_LIMIT');
    return new Uint8Array(value);
  }
}
/** Inspect native object graphs rather than scanning untrusted bytes for signature-looking strings. */
function structure(document: PDFDocument, policy: Limits) {
  let signed = false,
    active = false,
    count = 0;
  const seen = new Set<PDFObject>(),
    stack: Array<{ value: PDFObject; depth: number }> = [],
    maximum = Math.min(100000, Math.floor(policy.maxBytes / 8) + 1000),
    name = (input: PDFObject | undefined): string | undefined => {
      let value = input,
        depth = 0;
      while (value instanceof PDFRef) {
        if (++depth > 64) throw failure('EK_PDF_LIMIT');
        value = document.context.lookup(value);
        if (!value) throw failure();
      }
      if (!(value instanceof PDFName)) return undefined;
      const decoded = value.decodeText();
      // The pinned engine cannot reliably distinguish every lower-case escaped-name spelling.
      if (/#(?:[0-9A-Fa-f]{2})/.test(decoded)) throw failure();
      return decoded;
    };
  for (const [, value] of document.context.enumerateIndirectObjects())
    stack.push({ value, depth: 0 });
  while (stack.length) {
    const current = stack.pop()!;
    let value = current.value;
    if (value instanceof PDFRef) {
      const resolved = document.context.lookup(value);
      if (!resolved) throw failure();
      value = resolved;
    }
    if (!value || seen.has(value)) continue;
    seen.add(value);
    if (++count > maximum || current.depth > 64) throw failure('EK_PDF_LIMIT');
    const dictionary =
      value instanceof PDFRawStream ? value.dict : value instanceof PDFDict ? value : undefined;
    if (dictionary) {
      const keys = new Set<string>();
      for (const [key, child] of dictionary.entries()) {
        const label = name(key)!;
        keys.add(label);
        const kind = ['Type', 'FT', 'S'].includes(label) ? name(child) : undefined;
        if (
          (label === 'Type' && ['Sig', 'DocTimeStamp'].includes(kind ?? '')) ||
          (label === 'FT' && kind === 'Sig')
        )
          signed = true;
        if (
          label === 'S' &&
          [
            'JavaScript',
            'Launch',
            'SubmitForm',
            'ImportData',
            'GoToR',
            'Rendition',
            'RichMediaExecute',
          ].includes(kind ?? '')
        )
          active = true;
        if (
          [
            'JS',
            'JavaScript',
            'OpenAction',
            'AA',
            'XFA',
            'EmbeddedFiles',
            'RichMediaContent',
          ].includes(label)
        )
          active = true;
        stack.push({ value: child, depth: current.depth + 1 });
        if (stack.length > maximum) throw failure('EK_PDF_LIMIT');
      }
      if (keys.has('ByteRange') && keys.has('Contents')) signed = true;
    } else if (value instanceof PDFArray) {
      if (value.size() > maximum) throw failure('EK_PDF_LIMIT');
      for (let index = 0; index < value.size(); index++)
        stack.push({ value: value.get(index), depth: current.depth + 1 });
    }
  }
  return { signed, active };
}
async function load(source: Uint8Array, policy: Limits, modifying = false) {
  if (!source.length || source.length > policy.maxBytes) throw failure('EK_PDF_LIMIT');
  const document = await PDFDocument.load(source, {
    ignoreEncryption: false,
    updateMetadata: false,
    throwOnInvalidObject: true,
  });
  if (document.isEncrypted) throw failure();
  integer(document.getPageCount(), policy.maxPages);
  const flags = structure(document, policy);
  if (modifying && flags.signed) throw failure('EK_PDF_SIGNED');
  if (modifying && flags.active) throw failure();
  return { document, ...flags };
}
async function parsing(source: Uint8Array, policy: Limits) {
  const task = engine.getDocument({
    data: new Uint8Array(source),
    verbosity: 0,
    useWorkerFetch: false,
    BinaryDataFactory: LocalBinaryData,
    useSystemFonts: false,
    useWasm: false,
    stopAtErrors: true,
    maxImageSize: 0,
    canvasMaxAreaInBytes: 0,
    isOffscreenCanvasSupported: false,
    isImageDecoderSupported: false,
    disableFontFace: true,
    fontExtraProperties: false,
    enableXfa: false,
    disableRange: true,
    disableStream: true,
    disableAutoFetch: true,
  });
  try {
    const document = await task.promise;
    integer(document.numPages, policy.maxPages);
    return { task, document };
  } catch (error) {
    await task.destroy();
    throw error;
  }
}
function metadata(input: unknown): string | undefined {
  if (input === undefined || input === null) return undefined;
  if (typeof input !== 'string') throw failure();
  if (input.length > 4096 || Buffer.byteLength(input) > 4096) throw failure('EK_PDF_LIMIT');
  return [...input].filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) !== 127).join('');
}
async function inspect(source: Uint8Array, policy: Limits): Promise<PdfInfo> {
  const native = await load(source, policy),
    { document, task } = await parsing(source, policy);
  try {
    const { info } = await document.getMetadata();
    if (info.IsEncrypted === true || document.numPages !== native.document.getPageCount())
      throw failure();
    const title = metadata(info.Title),
      author = metadata(info.Author);
    return {
      pages: document.numPages,
      encrypted: false,
      signed: native.signed || info.IsSignaturesPresent === true,
      ...(title === undefined ? {} : { title }),
      ...(author === undefined ? {} : { author }),
    };
  } finally {
    await task.destroy();
  }
}
async function extract(
  source: Uint8Array,
  policy: Limits,
  maximum: number,
): Promise<readonly PdfTextPage[]> {
  await load(source, policy);
  const { document, task } = await parsing(source, policy),
    pages: PdfTextPage[] = [];
  let count = 0,
    size = 0;
  try {
    for (let index = 1; index <= document.numPages; index++) {
      const page = await document.getPage(index),
        reader = page
          .streamTextContent({ includeMarkedContent: false, disableNormalization: true })
          .getReader(),
        items: PdfTextItem[] = [];
      try {
        for (;;) {
          const next = await reader.read();
          if (next.done) break;
          for (const current of next.value.items) {
            if (
              typeof current.str !== 'string' ||
              !current.transform ||
              current.transform.length !== 6 ||
              !current.transform.every(Number.isFinite) ||
              !Number.isFinite(current.width) ||
              !Number.isFinite(current.height)
            )
              throw failure();
            if (
              ++count > policy.maxTextItems ||
              (size += Buffer.byteLength(current.str) + 160) > maximum
            )
              throw failure('EK_PDF_LIMIT');
            items.push({
              text: current.str,
              x: current.transform[4]!,
              y: current.transform[5]!,
              width: current.width!,
              height: current.height!,
            });
          }
        }
      } finally {
        await reader.cancel(new Error('Document text cursor closed'));
        reader.releaseLock();
        page.cleanup();
      }
      pages.push({ page: index, items });
    }
    return pages;
  } finally {
    await task.destroy();
  }
}
async function draw(document: PDFDocument, specs: Work['specs'], fonts: Work['fonts']) {
  document.registerFontkit(fontkit);
  const cache = new Map<string, PDFFont>(),
    characterSets = new Map<string, ReadonlySet<number>>();
  for (const spec of specs) {
    let font = cache.get(spec.font);
    if (!font) {
      if (builtins.has(spec.font)) font = await document.embedFont(spec.font as StandardFonts);
      else {
        const bytes = fonts[spec.font];
        if (!bytes) throw failure();
        font = await document.embedFont(bytes, { subset: true });
      }
      cache.set(spec.font, font);
      characterSets.set(spec.font, new Set(font.getCharacterSet()));
    }
    const supported = characterSets.get(spec.font)!;
    for (const character of spec.text) {
      const point = character.codePointAt(0)!;
      if (
        ![9, 10, 13].includes(point) &&
        !/\p{Cf}/u.test(character) &&
        !(point >= 0xfe00 && point <= 0xfe0f) &&
        !(point >= 0xe0100 && point <= 0xe01ef) &&
        !supported.has(point)
      )
        throw failure();
    }
    const page = document.getPage(spec.page - 1),
      hex = spec.colorHex.slice(1);
    page.drawText(spec.text, {
      x: spec.x,
      y: spec.y,
      font,
      size: spec.size,
      color: rgb(
        parseInt(hex.slice(0, 2), 16) / 255,
        parseInt(hex.slice(2, 4), 16) / 255,
        parseInt(hex.slice(4, 6), 16) / 255,
      ),
      rotate: degrees(spec.rotationDegrees),
    });
  }
}
async function save(document: PDFDocument, maximum: number) {
  document.setProducer('ArkenivaJS');
  document.setCreator('ArkenivaJS');
  document.setCreationDate(new Date(0));
  document.setModificationDate(new Date(0));
  const output = await document.save({
    useObjectStreams: true,
    addDefaultPage: false,
    updateFieldAppearances: false,
  });
  if (output.byteLength > maximum) throw failure('EK_PDF_LIMIT');
  return output;
}
/** All native parsing, font decoding and composition occur inside the owned child. */
export async function perform(
  work: Work,
  report: (pages: number) => void = () => undefined,
): Promise<PdfInfo | readonly PdfTextPage[] | Uint8Array> {
  const { operation, limits: policy, inputs, specs, maximum } = work;
  if (operation === 'inspect') {
    const value = await inspect(inputs[0]!, policy);
    report(value.pages);
    return value;
  }
  if (operation === 'extract') {
    const value = await extract(inputs[0]!, policy, maximum);
    report(value.length);
    return value;
  }
  if (operation === 'merge') {
    const result = await PDFDocument.create();
    let pages = 0;
    for (const bytes of inputs) {
      const { document } = await load(bytes, policy, true);
      pages += document.getPageCount();
      if (pages > policy.maxPages) throw failure('EK_PDF_LIMIT');
      for (const page of await result.copyPages(document, document.getPageIndices()))
        result.addPage(page);
    }
    report(pages);
    return save(result, maximum);
  }
  if (operation === 'add') {
    const { document } = await load(inputs[0]!, policy, true);
    if (specs.some((spec) => spec.page > document.getPageCount())) throw failure('EK_PDF_LIMIT');
    await draw(document, specs, work.fonts);
    report(document.getPageCount());
    return save(document, maximum);
  }
  const result = await PDFDocument.create(),
    count = specs.reduce((maximum, spec) => Math.max(maximum, spec.page), 1);
  integer(count, policy.maxPages);
  for (let index = 0; index < count; index++) result.addPage([595.28, 841.89]);
  await draw(result, specs, work.fonts);
  report(count);
  return save(result, maximum);
}
