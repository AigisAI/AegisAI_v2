import { loadAndValidateMultiClassCorpus } from './multi-class-corpus-loader.mjs';

const result = await loadAndValidateMultiClassCorpus();
const counts = result.classCounts
  .map((item) => `${item.corpusClass.toLowerCase()}=${item.cases}`)
  .join(', ');
process.stdout.write(
  `validated ${result.caseCount} T052 cases across ${result.fixtureCount} immutable fixtures (${counts}): ${result.snapshotDigest}\n`
);
