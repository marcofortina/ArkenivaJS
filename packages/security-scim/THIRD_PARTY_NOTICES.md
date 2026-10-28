# Third-party notices

This package uses SCIMMY 1.3.5 under the MIT license. The compatibility diff modifies only the distributed native ESM message implementation. Its pathless replacement correction follows the existing native explicit-path algorithm and the approach described in [upstream pull request 110](https://github.com/scimmyjs/scimmy/pull/110); out-of-range result pages are explicitly empty. The native filter, schema and patch implementations remain in SCIMMY. Review these assumptions and rerun conformance controls before changing versions. Original notice:

MIT License

Copyright (c) 2021 Sam Lee-Lindsay

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
