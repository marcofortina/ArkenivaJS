# JSON scanner declaration compatibility

The pinned `jsonc-parser` 3.3.1 package exports the `ScanError` and `SyntaxKind`
objects from its CommonJS runtime, but describes them as ambient `const enum`
declarations. TypeScript 6 rejects those imports with `verbatimModuleSyntax`.
The declaration patch describes the existing runtime enum objects as ordinary
enums. It changes two declaration lines and leaves the upstream JavaScript
unchanged. Strict compilation remains enabled.

The lexical scanner and visitor are used before `JSON.parse` to reject duplicate
decoded property names, comments, malformed tokens and excessive nesting. The
library's JSON-with-comments capabilities are never enabled for registry input.

Upstream: <https://github.com/microsoft/node-jsonc-parser> (MIT).
