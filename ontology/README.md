# Security Ontology CWE bootstrap

This directory provides a local, self-hosted Neo4j 5 Community stack and a bounded,
idempotent MITRE CWE importer. It is a dev/demo data bootstrap only. It does not replace
the active `006-production-sast-runtime-design` milestone, grant Scan Plane or AI Plane
authority, expose a GraphRAG route, or make Neo4j a production deployment dependency.

## Start Neo4j

Create a local environment file and set a unique password. Never commit that file or pass
the password as a command-line argument.

```bash
cd ontology
cp .env.example .env
# Edit .env and set NEO4J_PASSWORD to a generated, environment-specific value.
docker compose --env-file .env up -d
docker compose --env-file .env ps
```

Both Neo4j ports bind to `127.0.0.1` by default. `NEO4J_PLUGINS` installs APOC for this
local stack; the CWE importer itself uses only parameterized Cypher and does not require
APOC procedures. A production image must be independently digest-pinned, mirrored, and
approved under the repository's deployment and supply-chain contracts.

## Install and import

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --requirement requirements.txt
set -a
. ./.env
set +a
python load_cwe.py
```

The importer downloads only HTTPS input, caps the compressed and expanded sizes, verifies
an optional SHA-256 digest, accepts only UTF-8 XML, rejects decoded DTD/entity declarations,
and parses with entity and network resolution disabled. Neo4j credentials are read from the
environment; there is no password default or CLI password option.

For a reproducible import, download and review the archive separately, then provide its
digest:

```bash
python load_cwe.py \
  --archive ./cwec_latest.xml.zip \
  --sha256 <64-lowercase-hex-sha256> \
  --expect-cwe-count 969 \
  --expect-child-of-count 1160
```

The two expected counts above record the issue #276 acceptance baseline. MITRE's `latest`
archive is mutable, so a later catalog may legitimately require a reviewed count update.
Use `--dry-run` to download, validate, and summarize without connecting to Neo4j. Use
`--xml` for a previously extracted XML file and repeat `--cwe CWE-89 --cwe CWE-943` for a
bounded subset. A full import, with no `--cwe` options, is authoritative for the
`aegisai-cwe-importer-v1` snapshot: it removes stale importer-owned CWE nodes, hierarchy
edges, and orphaned mitigations in the same transaction. A subset import updates only the
selected CWE properties and mitigation edges; it deliberately preserves existing
`CHILD_OF` and `PEER_OF` edges because the selection cannot authoritatively replace the
complete hierarchy.

Development databases populated by an earlier unmarked importer do not have the
`managedBy` ownership property and are intentionally outside automated deletion. Reset the
local `ontology/data/` volume once before adopting this version instead of applying a broad,
unsafe cleanup to unowned graph nodes.

## Verify

```bash
python -m unittest discover -s tests -p 'test_*.py'
python -m compileall -q load_cwe.py tests
```

The importer verifies the persisted node and relationship totals for the selected source
set before returning success. Full imports also verify the total importer-owned CWE and
mitigation snapshots. Re-running the same catalog does not create duplicates.
