import { createHash } from 'node:crypto';

import {
  SAST_REPOSITORY_ENTRY_KINDS,
  SAST_PREFLIGHT_REASON_CODES,
  type SastPreflightDecision,
  type SastPreflightReasonCode,
  type SastRepositoryEntryClassification,
  type SastRepositoryPreflightInput,
  type SastRepositoryPreflightResult,
  type SastRepositoryTreeEntry
} from '@aegisai/shared';
import { BadRequestException, Injectable } from '@nestjs/common';

import { RepositoryPreflightAttestationService } from './repository-preflight-attestation.service';

const MAX_PATH_BYTES = 4096;
const DRIVE_ROOT = /^[A-Za-z]:/;
const ARCHIVE_SUFFIXES = [
  '.7z',
  '.bz2',
  '.ear',
  '.gz',
  '.jar',
  '.rar',
  '.tar',
  '.tar.bz2',
  '.tar.gz',
  '.tar.xz',
  '.tgz',
  '.war',
  '.xz',
  '.zip'
];
const VENDOR_SEGMENTS = new Set([
  'deps',
  'external',
  'node_modules',
  'third-party',
  'third_party',
  'vendor'
]);
const GENERATED_SEGMENTS = new Set(['build', 'dist', 'gen', 'generated', 'target']);
const FIXTURE_SEGMENTS = new Set([
  '__tests__',
  'fixture',
  'fixtures',
  'sample',
  'samples',
  'test',
  'tests'
]);
const REJECT_REASONS = new Set<SastPreflightReasonCode>([
  'PATH_INVALID_UTF8',
  'PATH_NUL_OR_CONTROL',
  'PATH_ABSOLUTE',
  'PATH_DRIVE_OR_UNC',
  'PATH_PARENT_TRAVERSAL',
  'PATH_LENGTH_LIMIT_EXCEEDED',
  'PATH_CASE_COLLISION',
  'PATH_UNICODE_COLLISION',
  'PATH_DUPLICATE',
  'SYMLINK_INVALID_UTF8',
  'SYMLINK_OUTSIDE_ROOT',
  'SYMLINK_CYCLE',
  'PATH_DEPTH_LIMIT_EXCEEDED',
  'REPOSITORY_BYTES_LIMIT_EXCEEDED',
  'SELECTED_BYTES_LIMIT_EXCEEDED',
  'FILE_COUNT_LIMIT_EXCEEDED',
  'SINGLE_FILE_BYTES_LIMIT_EXCEEDED'
]);
const RESTRICTED_REASONS = new Set<SastPreflightReasonCode>([
  'SYMLINK_PRESENT',
  'SUBMODULE_PRESENT',
  'LFS_POINTER_PRESENT'
]);

interface EvaluatedEntry {
  input: SastRepositoryTreeEntry;
  normalizedPath: string;
  normalizedTarget?: string;
  classification: SastRepositoryEntryClassification;
}

@Injectable()
export class RepositoryPreflightService {
  constructor(
    private readonly attestation: RepositoryPreflightAttestationService
  ) {}

  evaluate(input: SastRepositoryPreflightInput): SastRepositoryPreflightResult {
    this.validateInput(input);
    const reasons = new Set<SastPreflightReasonCode>();
    const rejectedPaths = new Set<string>();
    const exactPaths = new Map<string, string>();
    const caseFoldedPaths = new Map<string, string>();
    const evaluated: EvaluatedEntry[] = [];

    for (const entry of [...input.entries].sort((left, right) =>
      Buffer.from(left.path).compare(Buffer.from(right.path))
    )) {
      const normalizedPath = this.normalizePath(entry, reasons, rejectedPaths);
      if (normalizedPath) {
        this.detectCollisions(
          entry.path,
          normalizedPath,
          exactPaths,
          caseFoldedPaths,
          reasons,
          rejectedPaths
        );
      }
      const depth = normalizedPath ? normalizedPath.split('/').length : 0;
      if (depth > input.limits.maxPathDepth) {
        reasons.add('PATH_DEPTH_LIMIT_EXCEEDED');
        rejectedPaths.add(this.displayPath(entry.path));
      }
      if (entry.byteSize > input.limits.maxSingleFileBytes) {
        reasons.add('SINGLE_FILE_BYTES_LIMIT_EXCEEDED');
        rejectedPaths.add(this.displayPath(entry.path));
      }
      const normalizedTarget =
        entry.kind === 'SYMLINK' && normalizedPath
          ? this.resolveSymlink(
              normalizedPath,
              entry.symlinkTarget ?? '',
              entry.symlinkTargetEncodingValid ?? false,
              reasons,
              rejectedPaths
            )
          : undefined;
      evaluated.push({
        input: entry,
        normalizedPath,
        normalizedTarget,
        classification: this.classify(entry, normalizedPath, input)
      });
    }

    this.detectSymlinkCycles(evaluated, reasons, rejectedPaths);
    const counters = this.counters(evaluated);
    const repositoryBytes = this.safeSum(evaluated.map((entry) => entry.input.byteSize));
    const selectedBytes = this.safeSum(
      evaluated
        .filter((entry) => this.isSelected(entry.classification))
        .map((entry) => entry.input.byteSize)
    );
    let maxSingleFileBytes = 0;
    let maxPathDepth = 0;
    for (const entry of evaluated) {
      maxSingleFileBytes = Math.max(maxSingleFileBytes, entry.input.byteSize);
      maxPathDepth = Math.max(
        maxPathDepth,
        entry.normalizedPath ? entry.normalizedPath.split('/').length : 0
      );
    }

    if (input.entries.length > input.limits.maxFileCount) {
      reasons.add('FILE_COUNT_LIMIT_EXCEEDED');
    }
    if (repositoryBytes > input.limits.maxRepositoryBytes) {
      reasons.add('REPOSITORY_BYTES_LIMIT_EXCEEDED');
    }
    if (selectedBytes > input.limits.maxSelectedBytes) {
      reasons.add('SELECTED_BYTES_LIMIT_EXCEEDED');
    }
    if (counters.symlinkCount > 0) {
      reasons.add('SYMLINK_PRESENT');
    }
    if (counters.submoduleCount > 0) {
      reasons.add('SUBMODULE_PRESENT');
    }
    if (counters.lfsPointerCount > 0) {
      reasons.add('LFS_POINTER_PRESENT');
    }
    if (counters.archiveCount > 0) {
      reasons.add('ARCHIVE_PRESENT');
    }

    const reasonCodes = SAST_PREFLIGHT_REASON_CODES.filter((reason) => reasons.has(reason));
    const decision = this.decision(reasonCodes);
    const inventoryDigest = this.inventoryDigest(evaluated);
    const attestationRef = this.attestation.issue({
      attemptId: input.attemptId,
      fixedCommitSha: input.fixedCommitSha,
      pathPolicyVersion: input.pathPolicyVersion,
      inventoryDigest,
      decision
    });

    return {
      attemptId: input.attemptId,
      fixedCommitSha: input.fixedCommitSha,
      pathPolicyVersion: input.pathPolicyVersion,
      inventoryDigest,
      attestationRef,
      decision,
      reasonCodes,
      repositoryBytes,
      selectedBytes,
      maxSingleFileBytes,
      maxPathDepth,
      counts: counters,
      rejectedPaths: [...rejectedPaths].sort().slice(0, 100)
    };
  }

  private validateInput(input: SastRepositoryPreflightInput): void {
    if (
      !input.attemptId ||
      !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(input.fixedCommitSha) ||
      !input.pathPolicyVersion ||
      !Array.isArray(input.entries) ||
      input.pathPolicy.pathNormalizationRequired !== true ||
      input.pathPolicy.rejectAbsolutePaths !== true ||
      input.pathPolicy.rejectParentTraversal !== true ||
      input.pathPolicy.rejectCaseFoldCollisions !== true ||
      input.pathPolicy.symlinkPolicy !== 'REJECT_OUTSIDE_ROOT' ||
      input.pathPolicy.submodulePolicy !== 'DISABLED_BY_DEFAULT' ||
      input.pathPolicy.lfsPolicy !== 'POINTER_METADATA_ONLY_BY_DEFAULT' ||
      input.pathPolicy.archivePolicy !== 'DO_NOT_EXPAND' ||
      input.pathPolicy.generatedCodePolicy !== 'INDEX_BUT_SUPPRESS_BY_DEFAULT' ||
      input.pathPolicy.vendorCodePolicy !== 'DEPENDENCY_ONLY_BY_DEFAULT' ||
      input.pathPolicy.fixturePolicy !== 'SCAN_WITH_NON_BLOCKING_DEFAULT' ||
      !this.validPositiveLimit(input.limits.maxRepositoryBytes) ||
      !this.validPositiveLimit(input.limits.maxSelectedBytes) ||
      !this.validPositiveLimit(input.limits.maxFileCount) ||
      !this.validPositiveLimit(input.limits.maxSingleFileBytes) ||
      !this.validPositiveLimit(input.limits.maxPathDepth) ||
      !this.validStringList(input.sourceExtensions) ||
      !this.validStringList(input.manifestNames)
    ) {
      throw new BadRequestException('Repository preflight input is incomplete.');
    }
    const expectedObjectId =
      input.fixedCommitSha.length === 40
        ? /^sha1:[0-9a-f]{40}$/
        : /^sha256:[0-9a-f]{64}$/;
    for (const entry of input.entries) {
      if (
        !entry ||
        typeof entry.path !== 'string' ||
        typeof entry.pathEncodingValid !== 'boolean' ||
        !SAST_REPOSITORY_ENTRY_KINDS.includes(entry.kind) ||
        !Number.isSafeInteger(entry.byteSize) ||
        entry.byteSize < 0 ||
        typeof entry.gitObjectId !== 'string' ||
        !expectedObjectId.test(entry.gitObjectId) ||
        typeof entry.executable !== 'boolean' ||
        typeof entry.lfsPointer !== 'boolean' ||
        (entry.symlinkTarget !== undefined &&
          typeof entry.symlinkTarget !== 'string') ||
        (entry.symlinkTargetEncodingValid !== undefined &&
          typeof entry.symlinkTargetEncodingValid !== 'boolean') ||
        (entry.kind === 'SYMLINK' &&
          (typeof entry.symlinkTarget !== 'string' ||
            typeof entry.symlinkTargetEncodingValid !== 'boolean')) ||
        (entry.kind !== 'SYMLINK' &&
          (entry.symlinkTarget !== undefined ||
            entry.symlinkTargetEncodingValid !== undefined))
      ) {
        throw new BadRequestException('Repository preflight entry metadata is invalid.');
      }
    }
  }

  private validPositiveLimit(value: number): boolean {
    return Number.isSafeInteger(value) && value > 0;
  }

  private validStringList(value: readonly string[]): boolean {
    return (
      Array.isArray(value) &&
      value.length <= 256 &&
      value.every(
        (item) =>
          typeof item === 'string' &&
          item.length > 0 &&
          item.length <= 255 &&
          !hasControlCharacters(item)
      )
    );
  }

  private normalizePath(
    entry: SastRepositoryTreeEntry,
    reasons: Set<SastPreflightReasonCode>,
    rejectedPaths: Set<string>
  ): string {
    const display = this.displayPath(entry.path);
    if (!entry.pathEncodingValid) {
      reasons.add('PATH_INVALID_UTF8');
      rejectedPaths.add(display);
      return '';
    }
    if (hasControlCharacters(entry.path)) {
      reasons.add('PATH_NUL_OR_CONTROL');
      rejectedPaths.add(display);
      return '';
    }
    if (Buffer.byteLength(entry.path, 'utf8') > MAX_PATH_BYTES) {
      reasons.add('PATH_LENGTH_LIMIT_EXCEEDED');
      rejectedPaths.add(display);
      return '';
    }
    const separated = entry.path.replace(/\\/g, '/');
    if (
      separated.startsWith('/') ||
      entry.path.startsWith('\\\\') ||
      DRIVE_ROOT.test(separated)
    ) {
      reasons.add(
        entry.path.startsWith('\\\\') || DRIVE_ROOT.test(separated)
          ? 'PATH_DRIVE_OR_UNC'
          : 'PATH_ABSOLUTE'
      );
      rejectedPaths.add(display);
      return '';
    }
    const segments = separated.split('/');
    if (segments.includes('..')) {
      reasons.add('PATH_PARENT_TRAVERSAL');
      rejectedPaths.add(display);
      return '';
    }
    const normalized = segments
      .filter((segment) => segment && segment !== '.')
      .map((segment) => segment.normalize('NFC'))
      .join('/');
    if (!normalized) {
      reasons.add('PATH_PARENT_TRAVERSAL');
      rejectedPaths.add(display);
    }
    return normalized;
  }

  private detectCollisions(
    rawPath: string,
    normalizedPath: string,
    exactPaths: Map<string, string>,
    caseFoldedPaths: Map<string, string>,
    reasons: Set<SastPreflightReasonCode>,
    rejectedPaths: Set<string>
  ): void {
    const exact = exactPaths.get(normalizedPath);
    if (exact !== undefined) {
      reasons.add(exact === rawPath ? 'PATH_DUPLICATE' : 'PATH_UNICODE_COLLISION');
      rejectedPaths.add(this.displayPath(exact));
      rejectedPaths.add(this.displayPath(rawPath));
    } else {
      exactPaths.set(normalizedPath, rawPath);
    }

    const folded = normalizedPath.toLocaleLowerCase('en-US').normalize('NFC');
    const prior = caseFoldedPaths.get(folded);
    if (prior && prior !== normalizedPath) {
      reasons.add('PATH_CASE_COLLISION');
      rejectedPaths.add(this.displayPath(prior));
      rejectedPaths.add(this.displayPath(rawPath));
    } else {
      caseFoldedPaths.set(folded, normalizedPath);
    }
  }

  private resolveSymlink(
    path: string,
    target: string,
    targetEncodingValid: boolean,
    reasons: Set<SastPreflightReasonCode>,
    rejectedPaths: Set<string>
  ): string | undefined {
    if (!targetEncodingValid) {
      reasons.add('SYMLINK_INVALID_UTF8');
      rejectedPaths.add(this.displayPath(path));
      return undefined;
    }
    if (
      !target ||
      hasControlCharacters(target) ||
      target.startsWith('/') ||
      target.startsWith('\\\\') ||
      DRIVE_ROOT.test(target)
    ) {
      reasons.add('SYMLINK_OUTSIDE_ROOT');
      rejectedPaths.add(this.displayPath(path));
      return undefined;
    }
    const base = path.split('/').slice(0, -1);
    for (const segment of target.replace(/\\/g, '/').split('/')) {
      if (!segment || segment === '.') {
        continue;
      }
      if (segment === '..') {
        if (base.length === 0) {
          reasons.add('SYMLINK_OUTSIDE_ROOT');
          rejectedPaths.add(this.displayPath(path));
          return undefined;
        }
        base.pop();
      } else {
        base.push(segment.normalize('NFC'));
      }
    }
    return base.join('/');
  }

  private detectSymlinkCycles(
    entries: EvaluatedEntry[],
    reasons: Set<SastPreflightReasonCode>,
    rejectedPaths: Set<string>
  ): void {
    const links = new Map(
      entries
        .filter(
          (entry): entry is EvaluatedEntry & { normalizedTarget: string } =>
            entry.input.kind === 'SYMLINK' &&
            entry.normalizedTarget !== undefined
        )
        .map((entry) => [entry.normalizedPath, entry.normalizedTarget])
    );
    for (const start of links.keys()) {
      const visited = new Set<string>([start]);
      let cursor = links.get(start) ?? '';
      let cycleDetected = false;
      while (!cycleDetected) {
        const segments = cursor ? cursor.split('/') : [];
        let expanded = false;
        for (let index = 1; index <= segments.length; index += 1) {
          const linkPath = segments.slice(0, index).join('/');
          const replacement = links.get(linkPath);
          if (replacement === undefined) {
            continue;
          }
          if (visited.has(linkPath)) {
            cycleDetected = true;
            break;
          }
          visited.add(linkPath);
          cursor = [replacement, ...segments.slice(index)]
            .filter(Boolean)
            .join('/');
          expanded = true;
          break;
        }
        if (!expanded) {
          break;
        }
      }
      if (cycleDetected) {
        reasons.add('SYMLINK_CYCLE');
        for (const path of visited) {
          rejectedPaths.add(this.displayPath(path));
        }
      }
    }
  }

  private classify(
    entry: SastRepositoryTreeEntry,
    normalizedPath: string,
    input: SastRepositoryPreflightInput
  ): SastRepositoryEntryClassification {
    const lower = normalizedPath.toLocaleLowerCase('en-US').normalize('NFC');
    const segments = lower.split('/');
    const baseName = segments.at(-1) ?? '';
    if (entry.lfsPointer) {
      return 'LFS_POINTER';
    }
    if (ARCHIVE_SUFFIXES.some((suffix) => lower.endsWith(suffix))) {
      return 'ARCHIVE';
    }
    if (segments.some((segment) => VENDOR_SEGMENTS.has(segment))) {
      return 'VENDOR';
    }
    if (
      segments.some((segment) => GENERATED_SEGMENTS.has(segment)) ||
      /\.generated\.[^/]+$/.test(lower) ||
      lower.endsWith('.min.js')
    ) {
      return 'GENERATED';
    }
    if (segments.some((segment) => FIXTURE_SEGMENTS.has(segment))) {
      return 'FIXTURE';
    }
    if (segments.some((segment) => segment.startsWith('.'))) {
      return 'HIDDEN_SYSTEM';
    }
    if (input.manifestNames.some((name) => name.toLocaleLowerCase('en-US') === baseName)) {
      return 'MANIFEST';
    }
    if (
      input.sourceExtensions.some((extension) =>
        lower.endsWith(extension.toLocaleLowerCase('en-US'))
      )
    ) {
      return 'SOURCE';
    }
    return 'OTHER';
  }

  private counters(entries: EvaluatedEntry[]): SastRepositoryPreflightResult['counts'] {
    const directories = new Set<string>();
    for (const entry of entries) {
      const segments = entry.normalizedPath.split('/');
      for (let index = 1; index < segments.length; index += 1) {
        directories.add(segments.slice(0, index).join('/'));
      }
    }
    return {
      fileCount: entries.filter((entry) => entry.input.kind === 'FILE').length,
      directoryCount: directories.size,
      symlinkCount: entries.filter((entry) => entry.input.kind === 'SYMLINK').length,
      submoduleCount: entries.filter((entry) => entry.input.kind === 'SUBMODULE').length,
      lfsPointerCount: entries.filter((entry) => entry.input.lfsPointer).length,
      archiveCount: entries.filter((entry) => entry.classification === 'ARCHIVE').length,
      generatedCount: entries.filter((entry) => entry.classification === 'GENERATED').length,
      vendorCount: entries.filter((entry) => entry.classification === 'VENDOR').length,
      fixtureCount: entries.filter((entry) => entry.classification === 'FIXTURE').length,
      hiddenSystemCount: entries.filter(
        (entry) => entry.classification === 'HIDDEN_SYSTEM'
      ).length
    };
  }

  private isSelected(classification: SastRepositoryEntryClassification): boolean {
    return ['SOURCE', 'MANIFEST', 'GENERATED', 'FIXTURE'].includes(classification);
  }

  private safeSum(values: number[]): number {
    let total = 0;
    for (const value of values) {
      total += value;
      if (!Number.isSafeInteger(total)) {
        throw new BadRequestException('Repository byte counters exceed safe integer bounds.');
      }
    }
    return total;
  }

  private decision(reasonCodes: SastPreflightReasonCode[]): SastPreflightDecision {
    if (reasonCodes.some((reason) => REJECT_REASONS.has(reason))) {
      return 'REJECT';
    }
    if (reasonCodes.some((reason) => RESTRICTED_REASONS.has(reason))) {
      return 'RESTRICTED_ESCALATION';
    }
    return 'ACCEPT';
  }

  private inventoryDigest(entries: EvaluatedEntry[]): `sha256:${string}` {
    const records = entries
      .map((entry) =>
        Buffer.from(
          JSON.stringify([
            entry.normalizedPath,
            entry.input.pathEncodingValid,
            entry.input.kind,
            entry.input.byteSize,
            entry.input.gitObjectId,
            entry.input.executable,
            entry.normalizedTarget ?? null,
            entry.input.symlinkTargetEncodingValid ?? null,
            entry.input.lfsPointer,
            entry.classification
          ]),
          'utf8'
        )
      )
      .sort(Buffer.compare);
    const digest = createHash('sha256');
    for (const record of records) {
      const length = Buffer.allocUnsafe(4);
      length.writeUInt32BE(record.length);
      digest.update(length);
      digest.update(record);
    }
    return `sha256:${digest.digest('hex')}`;
  }

  private displayPath(path: string): string {
    return path
      .normalize('NFC')
      .split('')
      .map((character) => {
        const codePoint = character.codePointAt(0) ?? 0;
        return isUnsafeControlCodePoint(codePoint)
          ? `\\u{${codePoint.toString(16).padStart(4, '0')}}`
          : character;
      })
      .join('')
      .slice(0, 512);
  }
}

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((character) =>
    isUnsafeControlCodePoint(character.codePointAt(0) ?? 0)
  );
}

function isUnsafeControlCodePoint(codePoint: number): boolean {
  return (
    codePoint <= 31 ||
    (codePoint >= 127 && codePoint <= 159) ||
    codePoint === 0x061c ||
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069)
  );
}
