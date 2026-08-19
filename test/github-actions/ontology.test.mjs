import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const files = {
  compose: new URL('../../ontology/docker-compose.yml', import.meta.url),
  envExample: new URL('../../ontology/.env.example', import.meta.url),
  loader: new URL('../../ontology/load_cwe.py', import.meta.url),
  readme: new URL('../../ontology/README.md', import.meta.url),
  requirements: new URL('../../ontology/requirements.txt', import.meta.url),
  activeSpec: new URL(
    '../../specs/006-production-sast-runtime-design/spec.md',
    import.meta.url
  ),
  activePlan: new URL(
    '../../specs/006-production-sast-runtime-design/plan.md',
    import.meta.url
  ),
  activeTasks: new URL(
    '../../specs/006-production-sast-runtime-design/tasks.md',
    import.meta.url
  ),
  tests: new URL('../../ontology/tests/test_load_cwe.py', import.meta.url),
  workflow: new URL('../../.github/workflows/ci.yml', import.meta.url)
};

const read = (url) => readFileSync(url, 'utf8').replace(/\r\n/g, '\n');

test('ontology bootstrap is credential-safe and localhost-only by default', () => {
  for (const [name, url] of Object.entries(files)) {
    assert.equal(existsSync(url), true, `Expected ontology ${name} at ${url.pathname}`);
  }

  const compose = read(files.compose);
  const envExample = read(files.envExample);
  const loader = read(files.loader);

  assert.match(compose, /127\.0\.0\.1:\$\{NEO4J_HTTP_PORT:-7474\}:7474/);
  assert.match(compose, /127\.0\.0\.1:\$\{NEO4J_BOLT_PORT:-7687\}:7687/);
  assert.match(compose, /NEO4J_PASSWORD:\?Set NEO4J_PASSWORD/);
  assert.match(compose, /NEO4J_USERNAME=neo4j NEO4J_PASSWORD=/);
  assert.doesNotMatch(compose, /cypher-shell[^\n]*\s-p\s/);
  assert.match(compose, /no-new-privileges:true/);
  assert.doesNotMatch(compose, /aegisai123/);
  assert.match(envExample, /^NEO4J_PASSWORD=\s*$/m);
  assert.doesNotMatch(loader, /NEO4J_AUTH\s*=\s*\(/);
  assert.match(loader, /os\.getenv\("NEO4J_PASSWORD", ""\)/);
});

test('ontology importer applies bounded hostile-input validation', () => {
  const loader = read(files.loader);
  const readme = read(files.readme);

  assert.match(loader, /MAX_ARCHIVE_BYTES/);
  assert.match(loader, /MAX_XML_BYTES/);
  assert.match(loader, /MAX_COMPRESSION_RATIO/);
  assert.match(loader, /resolve_entities=False/);
  assert.match(loader, /no_network=True/);
  assert.match(loader, /load_dtd=False/);
  assert.match(loader, /DTD and entity declarations are not allowed/);
  assert.match(loader, /decode\("utf-8-sig"\)/);
  assert.match(loader, /getattr\(response, "history"/);
  assert.match(loader, /zlib\.error/);
  assert.match(loader, /expected_sha256/);
  assert.match(loader, /session\.execute_write\(write_catalog\)/);
  assert.match(loader, /managedBy/);
  assert.match(loader, /DETACH DELETE c/);
  assert.match(loader, /m\.cwe = row\.cwe/);
  assert.match(loader, /--dry-run/);
  assert.match(readme, /dev\/demo data bootstrap only/);
  assert.match(
    readme,
    /does not replace[\s\S]{0,320}006-production-sast-runtime-design/
  );
});

test('active 006 spec explicitly reclassifies only the bounded issue 276 bootstrap', () => {
  const spec = read(files.activeSpec);
  const plan = read(files.activePlan);
  const tasks = read(files.activeTasks);

  assert.match(spec, /Explicitly Reclassified Adjacent Bootstrap: Issue #276/);
  assert.match(spec, /MUST NOT receive Scan Plane, AI Plane, policy/);
  assert.match(spec, /does not[\s\S]{0,240}advance or satisfy T040/);
  assert.match(plan, /Issue #276 is an explicitly reclassified adjacent bootstrap/);
  assert.match(
    plan,
    /did not advance or satisfy T040[\s\S]{0,240}completed[\s\S]{0,180}T049[\s\S]{0,120}proceeds to T050/
  );
  assert.match(tasks, /Approved Adjacent Bootstrap \(Does Not Advance 006\)/);
  assert.match(tasks, /Keep T040 as the next formal active-milestone task/);
});

test('CI installs and exercises the ontology importer', () => {
  const workflow = read(files.workflow);
  const requirements = read(files.requirements);

  assert.match(workflow, /actions\/setup-python@v5/);
  assert.match(
    workflow,
    /python -m pip install .*--requirement ontology\/requirements\.txt/
  );
  assert.match(workflow, /python -m pip check/);
  assert.match(workflow, /docker compose -f ontology\/docker-compose\.yml config --quiet/);
  assert.match(
    workflow,
    /python -m unittest discover -s ontology\/tests -p 'test_\*\.py'/
  );
  assert.match(requirements, /neo4j>=5\.26\.0,<6\.0\.0/);
  assert.match(requirements, /lxml>=5\.3\.0,<7\.0\.0/);
  assert.match(requirements, /requests>=2\.32\.3,<3\.0\.0/);
});
