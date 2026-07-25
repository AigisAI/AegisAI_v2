# Trivy JSON v2 fixtures

These fixtures pin the AegisAI `trivy-json-normalizer-v1` contract to
Trivy v0.66.0 commit `7bcb181268893fdd69ef4582588c040bb1036c33`.

The accepted fixture combines the producer shapes represented by the upstream
v0.66.0 integration goldens:

- `integration/testdata/npm.json.golden`
- `integration/testdata/dockerfile.json.golden`
- `integration/testdata/secrets.json.golden`
- `integration/testdata/fixtures/convert/npm-with-suppressed.json.golden`

Fixture values are synthetic. Secret `Code`, `Match`, modified-finding
`Statement`, and `Source` values are deliberately present so tests can prove
that the adapter parses them only for bounded structure and never copies them
into a candidate, batch digest preimage, rejection, log, audit, API, or AI
payload.

`malicious-modified-license.trivy.json` proves that a modified finding cannot
cross the fixed Trivy responsibility boundary into an unsupported capability.
