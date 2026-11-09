# Integration readiness tasks

- [x] Define the user-authorized private-only preparation scope and keep 006 gates.
- [x] Integrate private contracts, API, generated DB client and existing UI theme.
- [x] Preserve existing migration history and explicit private image/compose paths.
- [x] Add independent-schema/client and deployment preflight guards.
- [ ] Run private API/UI, SQL and native-role acceptance without production writes.
- [ ] Pass existing dev and qualification checks alongside the private profile.
- [ ] Produce immutable candidate artifacts and read-only target readiness evidence.
- [x] Open mergeable review with exact validation and deployment boundary.
- [ ] Stop before production deployment; no live release action is authorized here.

Preparation-time status: [PR #339](https://github.com/AigisAI/AegisAI_v2/pull/339)
is mergeable. The first hosted run passed both API suites (private 99, general
812) but exposed expired August-dated T055/T056 CLI fixtures. Refresh only the
synthetic signed fixture chronology relative to execution time; preserve fixed
unit fixtures and every production verifier/signature/freshness restriction.
Final CI/artifact/target evidence is recorded on the PR after validation, avoiding
a new source commit solely to report that commit's artifact hashes.
