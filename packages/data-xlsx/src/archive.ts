// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { crc32 } from 'node:zlib';
import { isUtf8 } from 'node:buffer';
import { SaxesParser } from 'saxes';
import { fromBufferPromise, getFileNameLowLevel, parseExtraFields } from 'yauzl';
import type { Options } from './settings.js';
import { failure, sheetName, text, integer } from './validation.js';

export interface Inspection {
  readonly metadata: Map<string, Buffer>;
  readonly names: readonly string[];
  readonly cells: number;
  readonly rows: number;
  readonly expandedBytes: number;
  readonly cellValues: Map<string, Map<string, string | boolean | null>>;
}
const metadataParts = new Set([
  'xl/workbook.xml',
  'xl/_rels/workbook.xml.rels',
  'xl/sharedStrings.xml',
  'xl/styles.xml',
  'xl/theme/theme1.xml',
  '[Content_Types].xml',
]);
function address(value: string, options: Options): void {
  const match = /^([A-Z]{1,3})([1-9][0-9]{0,6})$/.exec(value);
  if (!match) throw failure();
  let column = 0;
  for (const character of match[1]!) column = column * 26 + character.charCodeAt(0) - 64;
  if (column > 16384 || Number(match[2]) > options.maxRowsPerSheet) throw failure('EK_XLSX_LIMIT');
}
/** Native SAX inspects structure and resource counts; ExcelJS remains the spreadsheet engine. */
function xmlGate(
  name: string,
  options: Options,
  state: {
    cells: number;
    rows: number;
    names: string[];
    values: Map<string, Map<string, string | boolean | null>>;
  },
) {
  const parser = new SaxesParser({ xmlns: false, position: false }),
    decoder = new TextDecoder('utf-8', { fatal: true });
  let depth = 0,
    sheetRows = 0,
    lastRow = 0,
    cellAddress = '',
    cellType = '',
    hasFormula = false,
    hasCached = false,
    inline = '',
    inlineCount = 0,
    inInline = false,
    cached = '',
    inCached = false,
    formula = '',
    inFormula = false;
  const worksheet = /^xl\/worksheets\/sheet[1-9][0-9]*\.xml$/.test(name),
    occupied = new Set<string>(),
    stack: string[] = [],
    styleCounts = new Map<string, number>();
  parser.on('doctype', () => {
    throw failure('EK_XLSX_UNSUPPORTED');
  });
  parser.on('error', () => {
    throw failure();
  });
  parser.on('xmldecl', (declaration) => {
    if (declaration.encoding && declaration.encoding.toLowerCase() !== 'utf-8')
      throw failure('EK_XLSX_UNSUPPORTED');
  });
  parser.on('opentag', (node) => {
    if (++depth > 64 || Object.keys(node.attributes).length > 64 || node.name.length > 256)
      throw failure('EK_XLSX_LIMIT');
    const attrs = node.attributes;
    if (
      (worksheet || ['xl/workbook.xml', 'xl/styles.xml', 'xl/sharedStrings.xml'].includes(name)) &&
      node.name.includes(':') &&
      [
        'workbook',
        'worksheet',
        'sheets',
        'sheet',
        'sheetData',
        'row',
        'c',
        'v',
        'is',
        't',
        'f',
        'sst',
        'si',
        'styleSheet',
        'fonts',
        'font',
        'numFmts',
        'numFmt',
        'cellXfs',
        'xf',
        'fills',
        'fill',
        'borders',
        'border',
      ].includes(node.name.split(':').at(-1)!)
    )
      throw failure('EK_XLSX_UNSUPPORTED');
    const parent = stack.at(-1);
    stack.push(node.name);
    for (const [key, value] of Object.entries(attrs))
      if (key.length > 256 || value.length > 16384) throw failure('EK_XLSX_LIMIT');
    if (name.endsWith('.rels') && node.name === 'Relationship') {
      const target = attrs.Target ?? '',
        mode = attrs.TargetMode ?? '',
        type = attrs.Type ?? '';
      if (
        mode.toLowerCase() === 'external' ||
        /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(target) ||
        target.startsWith('\\') ||
        /\/(?:externalLink|hyperlink|vbaProject)(?:Path)?$/.test(type)
      )
        throw failure('EK_XLSX_UNSUPPORTED');
      if (target.includes('\0') || target.length > 2048) throw failure();
    }
    if (
      name === '[Content_Types].xml' &&
      node.name === 'Override' &&
      /(?:macroEnabled|vbaProject|activeX|externalLink)/i.test(attrs.ContentType ?? '')
    )
      throw failure('EK_XLSX_UNSUPPORTED');
    if (name === 'xl/workbook.xml' && node.name === 'sheet') {
      const current = sheetName(attrs.name);
      if (
        state.names.length >= options.maxSheets ||
        state.names.some((previous) => previous.toLowerCase() === current.toLowerCase())
      )
        throw failure('EK_XLSX_LIMIT');
      state.names.push(current);
    }
    if (name === 'xl/styles.xml') {
      const maximum = Math.min(4096, options.maxCells + 1);
      const quota = ['fonts', 'numFmts'].includes(node.name) ? Math.min(256, maximum) : maximum;
      if (
        ['cellXfs', 'cellStyleXfs', 'fonts', 'numFmts', 'fills', 'borders'].includes(node.name) &&
        attrs.count !== undefined &&
        (!/^[0-9]+$/.test(attrs.count) || Number(attrs.count) > quota)
      )
        throw failure('EK_XLSX_LIMIT');
      if (
        parent &&
        ['cellXfs', 'cellStyleXfs', 'fonts', 'numFmts', 'fills', 'borders'].includes(parent)
      ) {
        const count = (styleCounts.get(parent) ?? 0) + 1;
        styleCounts.set(parent, count);
        if (count > (['fonts', 'numFmts'].includes(parent) ? Math.min(256, maximum) : maximum))
          throw failure('EK_XLSX_LIMIT');
      }
    }
    if (!worksheet) return;
    if (node.name === 'row') {
      const index = Number(attrs.r);
      integer(index, options.maxRowsPerSheet);
      if (index <= lastRow || ++sheetRows > options.maxRowsPerSheet) throw failure('EK_XLSX_LIMIT');
      lastRow = index;
      state.rows++;
    } else if (node.name === 'c') {
      cellAddress = text(attrs.r, 16);
      address(cellAddress, options);
      if (
        !cellAddress.endsWith(String(lastRow)) ||
        Number(/([0-9]+)$/.exec(cellAddress)![1]) !== lastRow ||
        occupied.has(cellAddress) ||
        ++state.cells > options.maxCells
      )
        throw failure('EK_XLSX_LIMIT');
      occupied.add(cellAddress);
      cellType = attrs.t ?? '';
      hasFormula = false;
      hasCached = false;
      inline = '';
      inlineCount = 0;
      cached = '';
      formula = '';
      if (cellType === 'e') throw failure('EK_XLSX_UNSUPPORTED');
      if (cellType === 'd') throw failure('EK_XLSX_UNSUPPORTED');
      if (!['', 'n', 's', 'b', 'inlineStr', 'str'].includes(cellType))
        throw failure('EK_XLSX_UNSUPPORTED');
    } else if (node.name === 'f') {
      hasFormula = true;
      inFormula = true;
      if (options.formulaPolicy === 'reject' || (attrs.t !== undefined && attrs.t !== 'normal'))
        throw failure('EK_XLSX_UNSUPPORTED');
    } else if (node.name === 'v') {
      inCached = true;
      hasCached = true;
    } else if (node.name === 't' && cellType === 'inlineStr') {
      if (++inlineCount > 1) throw failure('EK_XLSX_UNSUPPORTED');
      inInline = true;
    } else if (node.name === 'col') {
      integer(Number(attrs.min), 16384);
      integer(Number(attrs.max), 16384);
      if (Number(attrs.min) > Number(attrs.max)) throw failure();
    } else if (
      node.name === 'hyperlink' &&
      (attrs['r:id'] !== undefined || attrs.location !== undefined)
    )
      throw failure('EK_XLSX_UNSUPPORTED');
  });
  parser.on('text', (value) => {
    if (inInline) {
      inline += value;
      if (inline.length > 32767) throw failure('EK_XLSX_LIMIT');
    }
    if (inFormula) {
      formula += value;
      if (formula.length > 8192) throw failure('EK_XLSX_LIMIT');
    }
    if (inCached) {
      cached += value;
      if (cached.length > 131068) throw failure('EK_XLSX_LIMIT');
    }
  });
  parser.on('closetag', (node) => {
    stack.pop();
    if (worksheet && node.name === 'f') inFormula = false;
    if (worksheet && node.name === 'v') inCached = false;
    if (worksheet && node.name === 't') inInline = false;
    if (worksheet && node.name === 'c') {
      const remember = (value: string | boolean | null) => {
        let values = state.values.get(name);
        if (!values) state.values.set(name, (values = new Map()));
        values.set(cellAddress, value);
      };
      if (cellType === 'b' && hasCached && !['0', '1'].includes(cached)) throw failure();
      if (hasFormula && cellType === 'b' && hasCached) remember(cached === '1');
      else if (hasFormula && !hasCached) remember(null);
      else if (cellType === 'str' && hasCached) remember(cached);
      else if (cellType === 'inlineStr') remember(inline);
      if (
        hasCached &&
        ['', 'n'].includes(cellType) &&
        (!/^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[Ee][+-]?[0-9]+)?$/.test(cached) ||
          !Number.isFinite(Number(cached)))
      )
        throw failure();
      if (
        hasCached &&
        cellType === 's' &&
        (!/^[0-9]+$/.test(cached) || !Number.isSafeInteger(Number(cached)))
      )
        throw failure();
      if (hasFormula && options.formulaPolicy === 'preserve' && !formula.length)
        throw failure('EK_XLSX_UNSUPPORTED');
    }
    depth--;
  });
  return {
    push(chunk: Buffer, final = false) {
      try {
        const value = decoder.decode(chunk, { stream: !final });
        parser.write(value);
        if (final) parser.close();
      } catch (error) {
        if (error instanceof Error && 'code' in error) throw error;
        throw failure();
      }
    },
  };
}

/** Central/local headers, CRC and measured expansion are verified before native XLSX parsing. */
export async function inspect(input: Buffer, options: Options): Promise<Inspection> {
  if (input.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])))
    throw failure('EK_XLSX_UNSUPPORTED');
  const zip = await fromBufferPromise(input, {
    lazyEntries: true,
    decodeStrings: false,
    validateEntrySizes: true,
    strictFileNames: true,
  });
  const names = new Set<string>(),
    metadata = new Map<string, Buffer>(),
    state = {
      cells: 0,
      rows: 0,
      names: [] as string[],
      values: new Map<string, Map<string, string | boolean | null>>(),
    };
  let expandedBytes = 0,
    declared = 0;
  try {
    if (zip.entryCount > Math.min(10000, options.maxSheets * 32 + 256))
      throw failure('EK_XLSX_LIMIT');
    for await (const entry of zip.eachEntry()) {
      if (
        entry.fileNameRaw.some((byte) => byte < 32 || byte === 127) ||
        ((entry.generalPurposeBitFlag & 0x800) !== 0 && !isUtf8(entry.fileNameRaw))
      )
        throw failure();
      const name = getFileNameLowLevel(
        entry.generalPurposeBitFlag,
        entry.fileNameRaw,
        entry.extraFields,
        true,
      );
      if (
        name.includes('\\') ||
        name.startsWith('/') ||
        name.split('/').some((part) => ['.', '..'].includes(part)) ||
        names.has(name.toLowerCase()) ||
        name.length > 1024
      )
        throw failure();
      names.add(name.toLowerCase());
      const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
      if (
        (mode && ![0o040000, 0o100000].includes(mode)) ||
        entry.isEncrypted() ||
        !entry.canDecodeFileData()
      )
        throw failure('EK_XLSX_UNSUPPORTED');
      if (
        !Number.isSafeInteger(entry.uncompressedSize) ||
        entry.uncompressedSize < 0 ||
        (declared += entry.uncompressedSize) > options.maxUncompressedBytes ||
        entry.uncompressedSize > Math.max(1, entry.compressedSize) * 1000
      )
        throw failure('EK_XLSX_LIMIT');
      if (/(?:vbaProject|activeX|externalLinks)|\.bin$/i.test(name))
        throw failure('EK_XLSX_UNSUPPORTED');
      const local = await zip.readLocalFileHeaderPromise(entry);
      if (
        !local.fileName.equals(entry.fileNameRaw) ||
        local.compressionMethod !== entry.compressionMethod ||
        local.generalPurposeBitFlag !== entry.generalPurposeBitFlag ||
        getFileNameLowLevel(
          local.generalPurposeBitFlag,
          local.fileName,
          parseExtraFields(local.extraField),
          true,
        ) !== name
      )
        throw failure();
      const gate =
        name.endsWith('.xml') || name.endsWith('.rels') ? xmlGate(name, options, state) : undefined;
      const stream = await zip.openReadStreamPromise(entry),
        pieces: Buffer[] = [];
      let length = 0,
        checksum = 0;
      try {
        for await (const value of stream) {
          const chunk = Buffer.from(value as Uint8Array);
          length += chunk.length;
          expandedBytes += chunk.length;
          if (
            length > entry.uncompressedSize ||
            expandedBytes > options.maxUncompressedBytes ||
            length > Math.max(1, entry.compressedSize) * 1000
          )
            throw failure('EK_XLSX_LIMIT');
          checksum = crc32(chunk, checksum);
          gate?.push(chunk);
          if (metadataParts.has(name)) pieces.push(chunk);
        }
      } finally {
        stream.destroy();
      }
      gate?.push(Buffer.alloc(0), true);
      if (length !== entry.uncompressedSize || checksum !== entry.crc32) throw failure();
      if (metadataParts.has(name)) metadata.set(name, Buffer.concat(pieces));
    }
    if (
      !state.names.length ||
      !metadata.has('xl/workbook.xml') ||
      !metadata.has('xl/_rels/workbook.xml.rels') ||
      !metadata.has('[Content_Types].xml')
    )
      throw failure();
    return {
      metadata,
      names: Object.freeze(state.names),
      cells: state.cells,
      rows: state.rows,
      expandedBytes,
      cellValues: state.values,
    };
  } finally {
    zip.close();
  }
}
