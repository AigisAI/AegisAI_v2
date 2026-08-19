import { loadAndValidateSupplyChainRollbackQualificationPackage } from './supply-chain-rollback-qualification-loader.mjs';

const result = await loadAndValidateSupplyChainRollbackQualificationPackage();
if (
  result.qualificationStatus !== 'BLOCKED_T054_QUALIFICATION' ||
  result.t056EntryAuthorized !== false ||
  result.deploymentAuthority !== false ||
  result.productionReadinessAuthority !== false
) {
  throw new Error('repository-only T055 validation widened execution or readiness authority');
}
process.stdout.write(
  `validated ${result.executionCellCount} immutable T055 drill cells; external execution remains ${result.qualificationStatus} (${result.manifestDigest})\n`
);
