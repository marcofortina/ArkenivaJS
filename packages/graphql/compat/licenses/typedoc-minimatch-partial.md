# TypeDoc 0.28.20 compatibility with minimatch 11

This local adaptation changes only the published TypeDoc 0.28.20
`dist/node-utils.js` glob traversal. TypeDoc is an independent development
dependency distributed under [Apache-2.0](https://github.com/TypeStrong/typedoc/blob/v0.28.20/LICENSE).
Its original license and all other package contents remain unchanged.

The original npm archive has integrity
`sha512-uSKqkh8Cr48vllnEy+jdaAgOeR6Y+QCBW7usgUsKj7gJEfR7stw9U/fE49LBnj2tPRKPY0c0EBJSWe9Appmplg==`.
The archive deliberately excludes source maps, and the changed JavaScript has
no `sourceMappingURL`; this patch does not invent maps or change declarations.

minimatch 11 removes `Minimatch.matchOne()`, which TypeDoc used to determine
whether a directory could contain a matching descendant. The adaptation uses
a second official `Minimatch` with `flipNegate: true` and its public
`match(path, true)` partial-matching API. This preserves positive row-hit
semantics for traversal, including negated patterns. The original matcher
continues to decide full file matches with its original negation behavior.
Comments retain their original handling; the adaptation does not treat `!`
or `#` as literal prefixes by enabling `nonegate` or `nocomment`.

The matcher implementation, file discovery, `node_modules` restriction,
symlink handling and directory-inclusion policy remain upstream code. This
is a local compatibility adaptation, not an upstream TypeDoc release or an
authentication-policy change. ArkenivaJS modifications are identified in the
changed file; the framework license does not replace TypeDoc's license.

Upstream references:

- [TypeDoc filesystem utilities](https://github.com/TypeStrong/typedoc/blob/v0.28.20/src/lib/utils/fs.ts)
- [minimatch 11 changes](https://github.com/isaacs/minimatch/blob/v11.0.5/changelog.md)
- [minimatch matching options](https://github.com/isaacs/minimatch/blob/v11.0.5/README.md)
