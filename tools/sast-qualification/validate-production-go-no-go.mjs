import { loadAndValidateProductionGoNoGoPackage } from './production-go-no-go-loader.mjs';

const result = await loadAndValidateProductionGoNoGoPackage();
if (
  result.qualificationStatus !== 'BLOCKED_T055_QUALIFICATION' ||
  result.deploymentOperationsEntryAuthorized !== false ||
  result.deploymentAuthority !== false ||
  result.kubernetesExecutionAuthority !== false ||
  result.productionReadinessAuthority !== false
) {
  throw new Error('repository-only T056 validation widened deployment or readiness authority');
}
process.stdout.write(
  `validated ${result.gateCount} immutable T056 gates; external evidence remains ${result.qualificationStatus} (${result.manifestDigest})\n`
);
