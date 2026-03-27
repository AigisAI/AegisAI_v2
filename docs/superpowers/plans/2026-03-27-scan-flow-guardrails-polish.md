# #85 Scan Flow Guardrails And UX Polish Plan

1. Add failing frontend regressions for repository-to-scan continuity and scan guardrail states.
2. Update `/repos` to expose a direct scan-workspace CTA for the selected connected repository.
3. Update `/scan` to:
   - respect repository query parameters
   - surface connect-first and no-branch guardrails
   - redirect duplicate active branch requests toward the in-flight scan
   - improve selected scan status messaging
4. Apply minimal CSS polish required to support the new CTA and state treatments without drifting from the current Stitch baseline.
5. Run targeted frontend tests, then workspace `lint`, `test`, `typecheck`, and `build`.
