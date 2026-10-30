// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

// Generated once with pdf-lib 1.17.1: one A4 page, Helvetica 12, text at 40/700,
// fixed synthetic metadata and dates 2026-01-01T00:00:00Z; object streams disabled.
export const pdfInspectDescriptor = Object.freeze({
  bytes: 1301,
  pages: 1,
  sha256: '96a406656f863df530d5aa264f06ed5b365addbb7cdec5808173ceeced1e5799',
});
export const pdfInspectExpected = Object.freeze({
  pages: 1,
  encrypted: false,
  signed: false,
  title: 'owned-pdf-private-title',
  author: 'owned-pdf-private-author',
});
export const pdfInspectBase64 =
  'JVBERi0xLjcKJYGBgYEKCjEgMCBvYmoKPDwKL1R5cGUgL1BhZ2VzCi9LaWRzIFsgNSAwIFIgXQovQ291bnQgMQo+PgplbmRvYmoKCjIgMCBvYmoKPDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDEgMCBSCj4+CmVuZG9iagoKMyAwIG9iago8PAovUHJvZHVjZXIgPEZFRkYwMDZGMDA3NzAwNkUwMDY1MDA2NDAwMkQwMDcwMDA2NDAwNjYwMDJEMDA2NjAwNjkwMDc4MDA3NDAwNzUwMDcyMDA2NT4KL01vZERhdGUgKEQ6MjAyNjAxMDEwMDAwMDBaKQovQ3JlYXRvciA8RkVGRjAwNkYwMDc3MDA2RTAwNjUwMDY0MDAyRDAwNzAwMDY0MDA2NjAwMkQwMDY2MDA2OTAwNzgwMDc0MDA3NTAwNzIwMDY1PgovQ3JlYXRpb25EYXRlIChEOjIwMjYwMTAxMDAwMDAwWikKL1RpdGxlIDxGRUZGMDA2RjAwNzcwMDZFMDA2NTAwNjQwMDJEMDA3MDAwNjQwMDY2MDAyRDAwNzAwMDcyMDA2OTAwNzYwMDYxMDA3NDAwNjUwMDJEMDA3NDAwNjkwMDc0MDA2QzAwNjU+Ci9BdXRob3IgPEZFRkYwMDZGMDA3NzAwNkUwMDY1MDA2NDAwMkQwMDcwMDA2NDAwNjYwMDJEMDA3MDAwNzIwMDY5MDA3NjAwNjEwMDc0MDA2NTAwMkQwMDYxMDA3NTAwNzQwMDY4MDA2RjAwNzI+Cj4+CmVuZG9iagoKNCAwIG9iago8PAovVHlwZSAvRm9udAovU3VidHlwZSAvVHlwZTEKL0Jhc2VGb250IC9IZWx2ZXRpY2EKL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcKPj4KZW5kb2JqCgo1IDAgb2JqCjw8Ci9UeXBlIC9QYWdlCi9QYXJlbnQgMSAwIFIKL1Jlc291cmNlcyA8PAovRm9udCA8PAovSGVsdmV0aWNhLTcwOTg0ODA3ODkgNCAwIFIKPj4KL1hPYmplY3QgPDwKPj4KL0V4dEdTdGF0ZSA8PAo+Pgo+PgovTWVkaWFCb3ggWyAwIDAgNTk1LjI4IDg0MS44OSBdCi9Bbm5vdHMgWyBdCi9Db250ZW50cyBbIDYgMCBSIF0KPj4KZW5kb2JqCgo2IDAgb2JqCjw8Ci9GaWx0ZXIgL0ZsYXRlRGVjb2RlCi9MZW5ndGggMTE1Cj4+CnN0cmVhbQp4nB2KMQoCUQwF+5witSDmx+x7/4NYyK5Y2Ai5gMgqihaKeH5dmWIYmKdsUkwnXhdZ7Mb7Z3xfT8c5rdWoxtq0uOZZPDT3Uv5r0TClmeZDVtiSGNAhvKchgMl0NAKFgc574FfOJWOteZOcyZBykC8anxueCmVuZHN0cmVhbQplbmRvYmoKCnhyZWYKMCA3CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDAxNiAwMDAwMCBuIAowMDAwMDAwMDc2IDAwMDAwIG4gCjAwMDAwMDAxMjYgMDAwMDAgbiAKMDAwMDAwMDU5NyAwMDAwMCBuIAowMDAwMDAwNjk1IDAwMDAwIG4gCjAwMDAwMDA4OTYgMDAwMDAgbiAKCnRyYWlsZXIKPDwKL1NpemUgNwovUm9vdCAyIDAgUgovSW5mbyAzIDAgUgo+PgoKc3RhcnR4cmVmCjEwODQKJSVFT0Y=';

/** Return the same bounded synthetic document independently of the service under measurement. */
export function pdfInspectFixture() {
  const bytes = Buffer.from(pdfInspectBase64, 'base64');
  assert.equal(bytes.length, pdfInspectDescriptor.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), pdfInspectDescriptor.sha256);
  return bytes;
}
