import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const contractFile = new URL('../src/types/sast-planning.ts', import.meta.url);
const readContract = () => readFileSync(contractFile, 'utf8');

test('SAST planning contracts expose trusted metadata, profile, queue, and user-state boundaries', () => {
  assert.equal(existsSync(contractFile), true);
  const contract = readContract();

  for (const exportName of [
    'TrustedSastRepositoryMetadata',
    'SastProfileSelectionPolicy',
    'SastQueuePolicySet',
    'SastQueueUsageSnapshot',
    'SastUserVisiblePlanningState',
    'SastScanPlanningInput',
    'SastScanPlanningResult',
    'selectSastScanProfile',
    'evaluateSastQueueAdmission',
    'orderSastQueueCandidatesFairly',
    'buildSastCanonicalScanKeyPreimage'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type|function) ${exportName}\\b`));
  }
});

test('trusted planning metadata contains inventory attribution but no source or credential payload', () => {
  const contract = readContract();
  const metadataContract = contract
    .split('export interface TrustedSastRepositoryMetadata')[1]
    .split('export interface SastProfileSelectionPolicy')[0];

  for (const field of [
    'repositoryBindingId',
    'fixedCommitSha',
    'inventoryDigest',
    'attestationRef',
    'sourceLanguages',
    'manifestNames',
    'repositoryBytes',
    'selectedBytes',
    'fileCount',
    'maxSingleFileBytes',
    'maxPathDepth'
  ]) {
    assert.match(metadataContract, new RegExp(`\\b${field}\\b`));
  }

  for (const forbiddenField of [
    'sourceContent',
    'fileContent',
    'repositoryArchive',
    'credentialValue',
    'scmToken',
    'command',
    'environmentVariables'
  ]) {
    assert.doesNotMatch(metadataContract, new RegExp(`\\b${forbiddenField}\\b`, 'i'));
  }
});

test('profile selection fails closed for Fast unsupported languages and v1 polyglot scope', () => {
  const contract = readContract();

  assert.match(contract, /UNSUPPORTED_LANGUAGE_FOR_FAST/);
  assert.match(contract, /UNSUPPORTED_POLYGLOT_PROFILE/);
  assert.match(contract, /LANGUAGE_SPECIFIC_SAST_UNAVAILABLE/);
  assert.match(contract, /LANGUAGE_SPECIFIC_SAST_REQUIRED/);
  assert.match(contract, /SAST_SCAN_PROFILES\.JAVA_FAST_V1/);
  assert.match(contract, /SAST_SCAN_PROFILES\.JAVA_DEEP_V1/);
  assert.match(contract, /SAST_SCAN_PROFILES\.COMMON_DEEP_V1/);
});

test('canonical scan identity includes fixed source and every executable artifact digest', () => {
  const contract = readContract();
  const keyFunction = contract
    .split('export function buildSastCanonicalScanKeyPreimage')[1]
    .split('function rejectedProfileSelection')[0];

  for (const field of [
    'fixedCommitSha',
    'inventoryDigest',
    'profileDigest',
    'scannerSetDigest',
    'imageDigest',
    'wrapperDigest',
    'ruleBundles',
    'vulnerabilityDatabaseDigest',
    'schemaBundleDigest',
    'normalizerBundleDigest',
    'isolationClass'
  ]) {
    assert.match(keyFunction, new RegExp(`\\b${field}\\b`));
  }
});

test('queue admission is lane-separated, quota-bounded, and tenant-fair', () => {
  const contract = readContract();

  assert.match(contract, /queueName:\s*'scan\.fast\.v1'\s*\|\s*'scan\.deep\.v1'/);
  assert.match(contract, /fairnessStrategy:\s*'TENANT_ROUND_ROBIN'/);
  assert.match(contract, /TENANT_CONCURRENCY_LIMIT/);
  assert.match(contract, /TENANT_QUEUED_LIMIT/);
  assert.match(contract, /TENANT_DAILY_BUDGET_EXHAUSTED/);
  assert.match(contract, /QUEUE_USAGE_STALE/);
  assert.match(contract, /REPOSITORY_FREQUENCY_LIMIT/);
  assert.match(contract, /LANE_QUEUE_CAPACITY_EXHAUSTED/);
  assert.match(contract, /snapshotVersion:\s*number/);
  assert.match(contract, /rotateAfterTenant/);
});
