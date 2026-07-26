# Syft CycloneDX fixtures

- `upstream-compatible.cdx.json` is a minimized CycloneDX JSON 1.6 directory
  SBOM shaped from the pinned Syft v1.44.0 encoder contract. It retains the
  producer metadata, package/OS components, properties, licenses, and
  dependency graph needed to prove T034 behavior without copying an upstream
  repository fixture. The URL-empty Java `build-meta` reference mirrors
  Syft's archive-digest encoding; the npm website and Python VCS references
  mirror their metadata-specific encoders.
- Sentinel property values, source paths, prose, external-reference comments,
  and license URLs prove that the ingestor emits only bounded software
  inventory. The expected projection intentionally excludes raw BOM
  references and every discarded value.
- Tests mutate the golden fixture into malformed producer, identity, license,
  dependency, extension, nested-component, and resource-limit cases. Those
  mutations must reject the complete inventory batch. Producer-valid repeated
  license identities from different URLs are validated, discarded, and
  deterministically de-duplicated.
- Producer behavior is pinned to Syft commit
  `8cb78ce40ced6a731fb83f2a491a67444f541bf1`; schema behavior is pinned to
  CycloneDX specification commit
  `8a27bfd1be5be0dcb2c208a34d2f4fa0b6d75bd7`.
