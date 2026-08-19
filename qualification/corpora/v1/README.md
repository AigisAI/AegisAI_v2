# T051 Golden Qualification Corpus v1

This directory is the immutable, platform-owned input snapshot for T051. It contains no
customer repository data, credentials, executable configuration, dependency installation,
build step, dynamic test, or network requirement.

- `golden-corpus.snapshot.json` binds 400 positive and 400 paired negative cases.
- `prior-release-must-detect.manifest.json` independently authenticates the exact 400
  Critical/High positives released before this snapshot. Its reviewed digest is pinned in the
  generator; normal generation cannot recreate or overwrite it.
- New positives do not enter the prior must-detect denominator automatically. Every historical
  binding must still resolve to the identical case ID, digest, key, revision, rule, and severity.
- `sources/` contains 40 bounded UTF-8/LF source bundles. Each case binds an exact line range
  and a unique materialization path for later production-equivalent scanner tests.
- Negative kinds are assigned only where semantically applicable. The v1 counts are 95 patched,
  35 sanitizer, 95 safe-API, 80 comment/string, and 95 generated/vendor cases; generated/vendor
  cases retain the unsafe construct under an excluded path instead of duplicating comment cases.
- The generator and loader reject stale files, path escape, symlinks, non-UTF-8 or non-NFC
  content, CRLF ambiguity, oversized sources, digest/count/range drift, and unknown contract
  fields. Root entries are an exact allowlist, and file reads/writes use no-follow where the host
  supports it plus before/open/after identity checks to reject concurrent substitution.

Do not hand-edit generated files. Change the reviewed family definitions in
`tools/sast-qualification/golden-corpus-assets.mjs`, increment the immutable corpus revision,
build `@aegisai/shared`, add a new explicitly reviewed prior-release manifest/digest without
overwriting this one, regenerate the snapshot, and run the validator. The initialization flag is
bootstrap-only and refuses to run while the immutable manifest exists.

```powershell
corepack pnpm --filter @aegisai/shared build
node tools/sast-qualification/golden-corpus-assets.mjs
node tools/sast-qualification/validate-golden-corpus.mjs
```
