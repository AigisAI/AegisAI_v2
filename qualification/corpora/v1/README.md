# T051 Golden Qualification Corpus v1

This directory is the immutable, platform-owned input snapshot for T051. It contains no
customer repository data, credentials, executable configuration, dependency installation,
build step, dynamic test, or network requirement.

- `golden-corpus.snapshot.json` binds 400 positive and 400 paired negative cases.
- Every Critical/High positive case is included in the prior must-detect set.
- `sources/` contains 40 bounded UTF-8/LF source bundles. Each case binds an exact line range
  and a unique materialization path for later production-equivalent scanner tests.
- The generator and loader reject stale files, path escape, symlinks, non-UTF-8 or non-NFC
  content, CRLF ambiguity, oversized sources, digest/count/range drift, and unknown contract
  fields.

Do not hand-edit generated files. Change the reviewed family definitions in
`tools/sast-qualification/golden-corpus-assets.mjs`, increment the immutable corpus revision,
build `@aegisai/shared`, regenerate the snapshot, and run the validator.

```powershell
corepack pnpm --filter @aegisai/shared build
node tools/sast-qualification/golden-corpus-assets.mjs
node tools/sast-qualification/validate-golden-corpus.mjs
```
