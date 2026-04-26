# Language And Analysis Abstraction Design

## Goal

Implement the backend abstraction layers that keep the MVP Java-only while preserving clean
extension points for future languages and analysis providers.

## Scope

- Add `ILanguageHandler`, `LanguageHandlerRegistry`, and `JavaLanguageHandler`.
- Add `IAnalysisApiClient`, analysis request/result DTOs, `MockAnalysisApiClient`, and
  `AnalysisApiModule`.
- Export both abstraction layers so the upcoming scan module can consume them directly.
- Add focused tests for language registry behavior, Java file filtering rules, and mock
  analysis response shape.

## Out Of Scope

- `InternalAnalysisApiClient` implementation
- Scan service, scan processor, or code collector integration
- Repository persistence or controller endpoints
- Frontend analysis or language behavior

## Architecture

The `language` layer is a small plugin system. Each handler exposes its language key, allowed
file extensions, excluded path patterns, max file size, and a `supports(path)` decision helper.
`LanguageHandlerRegistry` owns handler lookup by language key and stays responsible only for
registration and retrieval.

The `analysis` layer stays behind `IAnalysisApiClient`. The default binding is
`MockAnalysisApiClient`, exported through `AnalysisApiModule` so later scan infrastructure can
depend on the interface token instead of a concrete implementation.

This keeps the MVP aligned with the spec: Java is the only registered language, and analysis is
delegated behind an interface instead of being implemented directly inside scan orchestration.

## Language Behavior

### JavaLanguageHandler

- language key: `java`
- allowed extensions: `.java`
- excluded patterns include test, generated, build, target, node_modules, and vendor paths
- maximum file size remains conservative for MVP collection so obviously generated or oversized
  files are screened out before analysis

The handler provides a `supports(path)` helper for extension checks. Path exclusion matching stays
available through the pattern list so the upcoming collector can apply it without hardcoding Java
rules elsewhere.

## Analysis Behavior

### IAnalysisApiClient

The interface receives a normalized `AnalysisRequest` with:

- `scanId`
- `language`
- `files[]` collected by the backend

The response shape preserves the consensus-oriented fields from the product spec:

- `success`
- `totalFiles`
- `totalLines`
- `vulnerabilities[]`
- `consensusScore`
- `modelResults`

### MockAnalysisApiClient

The mock implementation returns deterministic analysis data without network calls so MVP scan
infrastructure can be built and tested locally. It derives `totalFiles` and `totalLines` from the
request payload and returns at least one consensus-backed vulnerability fixture that later scan
persistence code can consume as-is.

## Module Wiring

- `LanguageModule` provides and exports `LanguageHandlerRegistry`
- `JavaLanguageHandler` is registered on module init
- `AnalysisApiModule` provides `MockAnalysisApiClient` and binds the `IAnalysisApiClient` token
  to it for Phase 1
- `AppModule` imports both modules so later features can inject them without additional
  infrastructure edits

## Testing Strategy

- Add language tests for:
  - Java handler metadata
  - extension support
  - registry lookup and unsupported language failure
- Add analysis tests for:
  - request-to-result totals in the mock client
  - consensus/model result preservation
  - module token binding to `MockAnalysisApiClient`
