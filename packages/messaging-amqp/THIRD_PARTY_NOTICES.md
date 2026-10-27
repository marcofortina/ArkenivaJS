<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native AMQP codec correction

The exact amqplib 2.2.0 compatibility diff retains its existing wire codec and
license. It preserves signed int64 values outside the JavaScript safe-integer
range as bigint, while keeping safe numeric results unchanged. It also builds
decoded field tables without an object prototype, preserving dangerous field
names for explicit adapter rejection. No wire encoding, delivery semantics,
cryptography or transport implementation is replaced.

## Upstream license

amqplib copyright (c) 2013, 2014
Michael Bridgen <mikeb@squaremobius.net>

This package, "amqplib", is licensed under the MIT License. A copy may
be found in the file LICENSE-MIT in this directory, or downloaded from
http://opensource.org/licenses/MIT.

The MIT License (MIT)

Copyright (c) 2013, 2014 Michael Bridgen <mikeb@squaremobius.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
