# T052 Multi-Class Qualification Corpus v1

This directory is the immutable, platform-owned input snapshot for T052. It contains no
customer repository data, executable configuration, real credentials, package installation,
build step, dynamic test, scanner execution, or network requirement.

- `multi-class-corpus.snapshot.json` binds 84 cases across schema/parser, malicious-repository,
  fingerprint/correlation, evidence/privacy, and performance classes.
- `fixtures/` contains canonical JSON recipes only. Hostile paths, invalid bytes, special files,
  large inputs, output pressure, and timeouts are represented as bounded data; this directory
  never contains a live symlink, FIFO, device, archive bomb, executable script, or expanded
  performance repository.
- T053 is the first stage allowed to interpret isolated-integration recipes inside a fresh
  production-equivalent sandbox. T054 owns end-to-end and performance measurements. A T052 pass
  authenticates inputs only and grants no finding, policy, publication, or readiness authority.
- Every performance size bucket requires 30 post-warm-up measurements on the single immutable
  hardware-class reference bound by the snapshot.
- Revision 1.0.1 binds every profile boundary to the selected profile's exact limit plus one,
  represents a symlink cycle as both directed links, carries binary/invalid-UTF-8 inputs as raw
  base64 bytes, and supplies complete fingerprint vectors whose excluded field alone changes.
- The generator and loader require exact root and fixture sets, canonical UTF-8/NFC/LF JSON,
  byte/digest identity, root confinement, no-follow file access where supported, and stable
  before/open/after filesystem identity.

Do not hand-edit generated assets. Change the reviewed scenario definitions in
`tools/sast-qualification/multi-class-corpus-assets.mjs`, increment the immutable revision,
regenerate, and run `corepack pnpm qualification:validate`. The initialization flag is
bootstrap-only and refuses to overwrite an existing corpus root.
