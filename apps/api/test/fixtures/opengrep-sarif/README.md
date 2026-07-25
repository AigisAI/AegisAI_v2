# OpenGrep SARIF normalizer fixtures

`upstream-compatible.sarif.json` follows the field ordering and shape emitted by
OpenGrep's `src/osemgrep/reporting/Sarif_output.ml` and its SARIF snapshots at upstream
commit `1bef4ea4ff3264754132eec823b5b1d8cde3e4ee` (2026-07-24).

The fixture intentionally contains:

- the official OASIS SARIF 2.1.0 schema URI;
- one `Opengrep OSS` run and successful invocation;
- rule-descriptor severity, confidence, CWE, and CVE tags;
- OpenGrep's `fingerprints["matchBasedId/v1"]`;
- the official `%SRCROOT%` primary-location base;
- ignored snippet content that must never enter a normalized candidate.

`malicious-ambiguous-location.sarif.json` is a fail-closed corpus case. A single
OpenGrep result cannot silently discard one of two primary locations.
