import { loadAndValidateEndToEndQualificationPackage } from './end-to-end-qualification-loader.mjs';

const result = await loadAndValidateEndToEndQualificationPackage();
if (
  result.qualificationStatus !== 'BLOCKED_T053_QUALIFICATION' ||
  result.t055EntryAuthorized !== false ||
  result.productionReadinessAuthority !== false
) {
  throw new Error('repository-only T054 validation widened execution or readiness authority');
}
process.stdout.write(
  `validated ${result.executionCellCount} immutable T054 execution cells; external execution remains ${result.qualificationStatus} (${result.manifestDigest})\n`
);
