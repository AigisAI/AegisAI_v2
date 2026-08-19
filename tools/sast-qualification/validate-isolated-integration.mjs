import { loadAndValidateIsolatedIntegrationPackage } from './isolated-integration-loader.mjs';

const result = await loadAndValidateIsolatedIntegrationPackage();
if (
  result.providerExecutionStatus !== 'PENDING_PROVIDER_EXECUTION' ||
  result.productionReadinessAuthority !== false
) {
  throw new Error('repository-only T053 validation widened provider or readiness authority');
}
process.stdout.write(
  `validated ${result.executionCellCount} immutable T053 provider-handoff cells; live evidence remains ${result.providerExecutionStatus} (${result.manifestDigest})\n`
);
