import { loadAndValidateGoldenCorpus } from './corpus-loader.mjs';

const result = await loadAndValidateGoldenCorpus();
process.stdout.write(
  `validated ${result.caseCount} T051 cases (${result.positiveCaseCount} positive, ${result.negativeCaseCount} negative, ${result.priorMustDetectCaseCount} prior must-detect) across ${result.sourceBundleCount} immutable source bundles: ${result.snapshotDigest}\n`
);
