import { createHash } from 'node:crypto';

import {
  buildSastIsolatedQualificationExecutionPlan,
  isSastIsolatedQualificationDependencySetValid
} from '../../packages/shared/dist/index.js';
import { loadAndValidateIsolatedIntegrationPackage } from './isolated-integration-loader.mjs';
import {
  parseExactArguments,
  readQualificationJson
} from './qualification-json-input.mjs';

const args = parseExactArguments(process.argv.slice(2), {
  '--dependency-set': true
});
const dependencyInput = await readQualificationJson(
  args['--dependency-set'],
  2 * 1024 * 1024,
  'T053 dependency set'
);
if (!isSastIsolatedQualificationDependencySetValid(dependencyInput.value, digest)) {
  throw new Error('T053 dependency set failed exact contract validation');
}
const qualificationPackage = await loadAndValidateIsolatedIntegrationPackage();
const plan = buildSastIsolatedQualificationExecutionPlan(
  {
    manifest: qualificationPackage.manifest,
    dependencySet: dependencyInput.value
  },
  digest
);
if (!plan) throw new Error('failed to create T053 provider execution plan');
process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
