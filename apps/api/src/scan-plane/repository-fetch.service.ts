import { createHash } from 'node:crypto';
import {
  chmod,
  constants,
  lstat,
  mkdtemp,
  mkdir,
  open,
  readlink,
  readdir,
  realpath,
  rm,
  unlink,
  writeFile
} from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { TextDecoder } from 'node:util';

import {
  type ScmProvider,
  type SastRepositoryFetchMetadata,
  type SastRepositoryTreeEntry,
  type TokenBrokerIssueRequest
} from '@aegisai/shared';
import { BadRequestException, Injectable } from '@nestjs/common';

import { ControlPlaneService } from '../control-plane/control-plane.service';
import { TokenBrokerService } from '../token-broker/token-broker.service';
import { CredentialTmpfsVerifier } from './credential-tmpfs-verifier.service';
import {
  RepositoryGitExecutor,
  type RepositoryGitCommandResult
} from './repository-git-executor';

const FULL_COMMIT_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SAFE_PREACCESS_PATH = /^(?!\/)(?![A-Za-z]:)(?!.*(?:^|\/)\.\.(?:\/|$)).+$/;
const GIT_COMMAND_TIMEOUT_MS = 120_000;
const TREE_ENRICHMENT_CONCURRENCY = 16;
const ALLOWED_GIT_TREE_ENTRIES = new Set([
  '100644:blob',
  '100755:blob',
  '120000:blob',
  '160000:commit'
]);

type ParsedGitTreeEntry = SastRepositoryTreeEntry;

export interface RepositoryFetchInput {
  scratchRoot: string;
  workspaceRoot: string;
  credentialTmpfsRoot: string;
  tokenRequest: TokenBrokerIssueRequest;
}

export interface RepositoryFetchResult {
  metadata: SastRepositoryFetchMetadata;
  workspaceRoot: string;
  entries: SastRepositoryTreeEntry[];
}

@Injectable()
export class RepositoryFetchService {
  constructor(
    private readonly tokenBroker: TokenBrokerService,
    private readonly git: RepositoryGitExecutor,
    private readonly controlPlane: ControlPlaneService,
    private readonly credentialTmpfsVerifier: CredentialTmpfsVerifier
  ) {}

  async fetch(input: RepositoryFetchInput): Promise<RepositoryFetchResult> {
    this.validateInput(input);
    const target = await this.controlPlane.getRepositoryFetchTarget(
      input.tokenRequest.tenantId,
      input.tokenRequest.repositoryBindingId
    );
    const remote = this.buildRemote(target.provider, target.fullName);
    await this.prepareEmptyWorkspace(input.scratchRoot, input.workspaceRoot);
    const credentialDirectory = await this.createCredentialDirectory(
      input.scratchRoot,
      input.credentialTmpfsRoot
    );

    try {
      return await this.tokenBroker.withCredential(input.tokenRequest, async (credential) => {
        let environment: Record<string, string> | undefined;
        let remoteAdded = false;
        try {
          environment = await this.createGitEnvironment(
            credentialDirectory,
            credential,
            target.provider
          );
          await this.run(input.workspaceRoot, environment, ['init', '--quiet', '.']);
          await this.run(input.workspaceRoot, environment, [
            'remote',
            'add',
            'origin',
            remote.toString()
          ]);
          remoteAdded = true;
          await this.run(input.workspaceRoot, environment, [
            'config',
            '--local',
            'fetch.recurseSubmodules',
            'false'
          ]);
          await this.run(input.workspaceRoot, environment, [
            'config',
            '--local',
            'submodule.recurse',
            'false'
          ]);
          await this.run(input.workspaceRoot, environment, [
            'fetch',
            '--quiet',
            '--no-tags',
            '--depth=1',
            '--no-recurse-submodules',
            'origin',
            input.tokenRequest.commitSha
          ]);

          const fetchedCommit = this.singleLine(
            await this.run(input.workspaceRoot, environment, [
              'rev-parse',
              'FETCH_HEAD^{commit}'
            ])
          );
          if (fetchedCommit !== input.tokenRequest.commitSha) {
            throw new BadRequestException('Fetched commit does not match the immutable scan SHA.');
          }

          await this.run(input.workspaceRoot, environment, [
            'checkout',
            '--quiet',
            '--detach',
            '--force',
            input.tokenRequest.commitSha
          ]);
          const headCommit = this.singleLine(
            await this.run(input.workspaceRoot, environment, ['rev-parse', 'HEAD'])
          );
          if (headCommit !== input.tokenRequest.commitSha) {
            throw new BadRequestException('Detached checkout does not match the fixed commit SHA.');
          }
          const shallow = this.singleLine(
            await this.run(input.workspaceRoot, environment, [
              'rev-parse',
              '--is-shallow-repository'
            ])
          );
          if (shallow !== 'true') {
            throw new BadRequestException('Repository fetch did not produce a shallow checkout.');
          }

          const tree = await this.run(input.workspaceRoot, environment, [
            'ls-tree',
            '-r',
            '-z',
            '-l',
            'HEAD'
          ]);
          const entries = await this.enrichEntries(
            input.workspaceRoot,
            this.parseTree(tree.stdout, input.tokenRequest.commitSha.length)
          );
          const countObjects = this.singleLineBlock(
            await this.run(input.workspaceRoot, environment, ['count-objects', '-v'])
          );
          const counts = this.parseObjectCounts(countObjects);
          await this.run(input.workspaceRoot, environment, [
            'remote',
            'remove',
            'origin'
          ]);
          remoteAdded = false;
          await this.removeGitMetadata(input.workspaceRoot);

          return {
            metadata: {
              attemptId: input.tokenRequest.attemptId,
              fixedCommitSha: input.tokenRequest.commitSha,
              remoteHost: remote.hostname.toLowerCase(),
              objectCount: counts.objectCount,
              fetchedBytes: counts.fetchedBytes,
              shallow: true,
              detachedHead: true,
              submodulesFetched: false,
              lfsObjectsFetched: false,
              archivesExpanded: false,
              gitMetadataRemoved: true,
              credentialWiped: true
            },
            workspaceRoot: resolve(input.workspaceRoot),
            entries
          };
        } finally {
          if (remoteAdded && environment) {
            await this.run(input.workspaceRoot, environment, [
              'remote',
              'remove',
              'origin'
            ]).catch(() => undefined);
          }
          await this.destroyCredentialFiles(credentialDirectory, credential.byteLength);
        }
      });
    } finally {
      await this.removeCredentialDirectory(input.scratchRoot, credentialDirectory);
    }
  }

  private validateInput(input: RepositoryFetchInput): void {
    if (
      !FULL_COMMIT_SHA.test(input.tokenRequest.commitSha) ||
      input.tokenRequest.principal !== 'REPO_READ'
    ) {
      throw new BadRequestException('Repository fetch requires a full fixed commit and REPO_READ.');
    }
    this.assertDisjointPaths(input.workspaceRoot, input.credentialTmpfsRoot);
  }

  private buildRemote(provider: ScmProvider, fullName: string): URL {
    const githubName = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
    const gitlabName = /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/;
    const pathSegments = fullName.split('/');
    if (
      fullName.length > 512 ||
      (provider === 'GITHUB' && !githubName.test(fullName)) ||
      (provider === 'GITLAB' && !gitlabName.test(fullName)) ||
      pathSegments.some(
        (segment) =>
          segment === '.' || segment === '..' || segment.length > 255
      )
    ) {
      throw new BadRequestException('Durable repository name is outside the SCM path policy.');
    }
    const expectedHost = provider === 'GITHUB' ? 'github.com' : 'gitlab.com';
    const remote = new URL(`https://${expectedHost}/${fullName}.git`);
    if (
      remote.protocol !== 'https:' ||
      remote.hostname.toLowerCase() !== expectedHost ||
      remote.username ||
      remote.password ||
      remote.port ||
      remote.search ||
      remote.hash
    ) {
      throw new BadRequestException('Repository remote is outside the approved SCM host policy.');
    }
    return remote;
  }

  private async prepareEmptyWorkspace(scratchRoot: string, workspaceRoot: string): Promise<void> {
    this.assertDescendant(scratchRoot, workspaceRoot, 'workspace');
    await this.assertRealDirectory(scratchRoot, 'scratch root');
    await this.ensureRealDirectoryPath(
      scratchRoot,
      dirname(resolve(workspaceRoot)),
      'workspace parent'
    );
    try {
      await mkdir(resolve(workspaceRoot), { recursive: false });
    } catch {
      const entries = await readdir(resolve(workspaceRoot)).catch(() => null);
      if (!entries || entries.length !== 0) {
        throw new BadRequestException('Repository workspace must be new or empty.');
      }
    }
    await this.assertRealDescendant(scratchRoot, workspaceRoot, 'workspace');
  }

  private async createCredentialDirectory(
    scratchRoot: string,
    credentialTmpfsRoot: string
  ): Promise<string> {
    this.assertDescendant(scratchRoot, credentialTmpfsRoot, 'credential tmpfs');
    await this.assertRealDirectory(scratchRoot, 'scratch root');
    await this.ensureRealDirectoryPath(
      scratchRoot,
      credentialTmpfsRoot,
      'credential tmpfs'
    );
    await chmod(resolve(credentialTmpfsRoot), 0o700);
    await this.assertRealDescendant(
      scratchRoot,
      credentialTmpfsRoot,
      'credential tmpfs'
    );
    await this.credentialTmpfsVerifier.assertTmpfs(resolve(credentialTmpfsRoot));
    const directory = await mkdtemp(join(resolve(credentialTmpfsRoot), 'aegis-credential-'));
    this.assertDescendant(credentialTmpfsRoot, directory, 'credential lease');
    await chmod(directory, 0o700);
    await this.assertRealDescendant(
      credentialTmpfsRoot,
      directory,
      'credential lease'
    );
    return directory;
  }

  private async createGitEnvironment(
    credentialDirectory: string,
    credential: Uint8Array,
    provider: ScmProvider
  ): Promise<Record<string, string>> {
    const credentialPath = join(credentialDirectory, 'credential');
    const askPassPath = join(credentialDirectory, 'askpass.sh');
    const globalConfigPath = join(credentialDirectory, 'gitconfig');
    await writeFile(credentialPath, credential, { mode: 0o600, flag: 'wx' });
    await writeFile(
      askPassPath,
      [
        '#!/bin/sh',
        'case "$1" in',
        '  *Username*) printf "%s\\n" "$AEGIS_GIT_USERNAME" ;;',
        '  *) exec /bin/cat "$AEGIS_CREDENTIAL_FILE" ;;',
        'esac',
        ''
      ].join('\n'),
      { mode: 0o700, flag: 'wx' }
    );
    await writeFile(globalConfigPath, '', { mode: 0o600, flag: 'wx' });

    return {
      GIT_ASKPASS: askPassPath,
      GIT_TERMINAL_PROMPT: '0',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: globalConfigPath,
      GIT_LFS_SKIP_SMUDGE: '1',
      GIT_OPTIONAL_LOCKS: '0',
      AEGIS_CREDENTIAL_FILE: credentialPath,
      AEGIS_GIT_USERNAME: provider === 'GITHUB' ? 'x-access-token' : 'oauth2'
    };
  }

  private async destroyCredentialFiles(
    credentialDirectory: string,
    credentialBytes: number
  ): Promise<void> {
    const credentialPath = join(credentialDirectory, 'credential');
    await writeFile(credentialPath, Buffer.alloc(credentialBytes), {
      mode: 0o600,
      flag: 'w'
    }).catch(() => undefined);
    await Promise.all([
      unlink(credentialPath).catch(() => undefined),
      unlink(join(credentialDirectory, 'askpass.sh')).catch(() => undefined),
      unlink(join(credentialDirectory, 'gitconfig')).catch(() => undefined)
    ]);
  }

  private async removeCredentialDirectory(
    scratchRoot: string,
    credentialDirectory: string
  ): Promise<void> {
    this.assertDescendant(scratchRoot, credentialDirectory, 'credential cleanup');
    await this.assertRealDescendant(
      scratchRoot,
      credentialDirectory,
      'credential cleanup'
    );
    await rm(credentialDirectory, { recursive: true, force: true });
  }

  private async removeGitMetadata(workspaceRoot: string): Promise<void> {
    const gitMetadataPath = resolve(workspaceRoot, '.git');
    this.assertDescendant(workspaceRoot, gitMetadataPath, 'git metadata cleanup');
    await this.assertRealDescendant(
      workspaceRoot,
      gitMetadataPath,
      'git metadata cleanup'
    );
    await rm(gitMetadataPath, { recursive: true, force: true });
  }

  private async run(
    cwd: string,
    environment: Record<string, string>,
    args: string[]
  ): Promise<RepositoryGitCommandResult> {
    return this.git.run({
      args,
      cwd,
      environment,
      timeoutMilliseconds: GIT_COMMAND_TIMEOUT_MS
    });
  }

  private parseTree(
    output: Buffer,
    expectedObjectIdLength: number
  ): ParsedGitTreeEntry[] {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    return output
      .subarray(0, output.length > 0 && output[output.length - 1] === 0 ? -1 : undefined)
      .toString('binary')
      .split('\0')
      .filter(Boolean)
      .map((binaryRecord) => {
        const record = Buffer.from(binaryRecord, 'binary');
        const tab = record.indexOf(0x09);
        if (tab < 0) {
          throw new BadRequestException('Git tree inventory record is malformed.');
        }
        const header = record.subarray(0, tab).toString('ascii');
        const match =
          /^(\d{6}) (blob|commit) ([0-9a-f]{40}|[0-9a-f]{64})\s+(-|\d+)$/.exec(
            header
          );
        if (!match) {
          throw new BadRequestException('Git tree inventory metadata is malformed.');
        }
        if (match[3].length !== expectedObjectIdLength) {
          throw new BadRequestException(
            'Git tree object format does not match the fixed commit.'
          );
        }
        const pathBytes = record.subarray(tab + 1);
        let path: string;
        let pathEncodingValid = true;
        try {
          path = decoder.decode(pathBytes);
        } catch {
          pathEncodingValid = false;
          path = `[invalid-utf8:${createHash('sha256')
            .update(pathBytes)
            .digest('hex')
            .slice(0, 16)}]`;
        }
        const mode = match[1];
        const objectType = match[2];
        const rawByteSize = match[4];
        const byteSize = rawByteSize === '-' ? 0 : Number(rawByteSize);
        if (
          !ALLOWED_GIT_TREE_ENTRIES.has(`${mode}:${objectType}`) ||
          (objectType === 'commit' && rawByteSize !== '-') ||
          (objectType === 'blob' && rawByteSize === '-') ||
          !Number.isSafeInteger(byteSize) ||
          byteSize < 0
        ) {
          throw new BadRequestException('Git tree entry type or size is outside policy.');
        }
        return {
          path,
          pathEncodingValid,
          kind:
            mode === '120000'
              ? 'SYMLINK'
              : mode === '160000' || objectType === 'commit'
                ? 'SUBMODULE'
                : 'FILE',
          byteSize,
          gitObjectId: `${
            match[3].length === 40 ? 'sha1' : 'sha256'
          }:${match[3]}` as `sha1:${string}` | `sha256:${string}`,
          executable: mode === '100755',
          lfsPointer: false
        };
      });
  }

  private async enrichEntries(
    workspaceRoot: string,
    entries: ParsedGitTreeEntry[]
  ): Promise<SastRepositoryTreeEntry[]> {
    const enriched = new Array<SastRepositoryTreeEntry>(entries.length);
    let cursor = 0;
    let failed = false;
    let firstError: unknown;
    const worker = async () => {
      while (!failed && cursor < entries.length) {
        const index = cursor;
        cursor += 1;
        try {
          enriched[index] = await this.enrichEntry(workspaceRoot, entries[index]);
        } catch (error) {
          failed = true;
          firstError = error;
        }
      }
    };
    await Promise.all(
      Array.from(
        { length: Math.min(TREE_ENRICHMENT_CONCURRENCY, entries.length) },
        worker
      )
    );
    if (failed) {
      throw firstError;
    }
    return enriched;
  }

  private async enrichEntry(
    workspaceRoot: string,
    parsedEntry: ParsedGitTreeEntry
  ): Promise<SastRepositoryTreeEntry> {
    const entry: SastRepositoryTreeEntry = {
      path: parsedEntry.path,
      pathEncodingValid: parsedEntry.pathEncodingValid,
      kind: parsedEntry.kind,
      byteSize: parsedEntry.byteSize,
      gitObjectId: parsedEntry.gitObjectId,
      executable: parsedEntry.executable,
      symlinkTarget: parsedEntry.symlinkTarget,
      symlinkTargetEncodingValid: parsedEntry.symlinkTargetEncodingValid,
      lfsPointer: parsedEntry.lfsPointer
    };
    if (
      !entry.pathEncodingValid ||
      hasControlCharacters(entry.path) ||
      !SAFE_PREACCESS_PATH.test(entry.path)
    ) {
      return entry;
    }
    const absolutePath = resolve(workspaceRoot, ...entry.path.split('/'));
    this.assertDescendant(workspaceRoot, absolutePath, 'repository entry');
    if (entry.kind === 'SYMLINK') {
      const targetBytes = await readlink(absolutePath, { encoding: 'buffer' });
      const decoder = new TextDecoder('utf-8', { fatal: true });
      try {
        return {
          ...entry,
          symlinkTarget: decoder.decode(targetBytes),
          symlinkTargetEncodingValid: true
        };
      } catch {
        return {
          ...entry,
          symlinkTarget: `[invalid-utf8:${createHash('sha256')
            .update(targetBytes)
            .digest('hex')
            .slice(0, 16)}]`,
          symlinkTargetEncodingValid: false
        };
      }
    }
    if (entry.kind !== 'FILE' || entry.byteSize > 1024) {
      return entry;
    }

    const handle = await open(
      absolutePath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
    );
    try {
      const prefix = Buffer.alloc(Math.min(entry.byteSize, 256));
      await handle.read(prefix, 0, prefix.length, 0);
      return {
        ...entry,
        lfsPointer: prefix
          .toString('utf8')
          .startsWith('version https://git-lfs.github.com/spec/v1\n')
      };
    } finally {
      await handle.close();
    }
  }

  private parseObjectCounts(output: string): { objectCount: number; fetchedBytes: number } {
    const values = new Map<string, number>();
    for (const line of output.split(/\r?\n/).filter(Boolean)) {
      const match = /^([a-z-]+):\s+(\d+)$/.exec(line);
      if (!match || values.has(match[1])) {
        throw new BadRequestException('Git object metadata is invalid.');
      }
      const value = Number(match[2]);
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new BadRequestException('Git object metadata is invalid.');
      }
      values.set(match[1], value);
    }
    for (const required of ['count', 'in-pack', 'size', 'size-pack']) {
      if (!values.has(required)) {
        throw new BadRequestException('Git object metadata is incomplete.');
      }
    }
    const objectCount = (values.get('count') ?? 0) + (values.get('in-pack') ?? 0);
    const fetchedKiB = (values.get('size') ?? 0) + (values.get('size-pack') ?? 0);
    const fetchedBytes = fetchedKiB * 1024;
    if (
      !Number.isSafeInteger(objectCount) ||
      !Number.isSafeInteger(fetchedBytes)
    ) {
      throw new BadRequestException('Git object metadata is invalid.');
    }
    return {
      objectCount,
      fetchedBytes
    };
  }

  private singleLine(result: RepositoryGitCommandResult): string {
    return result.stdout.toString('utf8').trim();
  }

  private singleLineBlock(result: RepositoryGitCommandResult): string {
    return result.stdout.toString('utf8').trim();
  }

  private assertDescendant(root: string, target: string, label: string): void {
    const resolvedRoot = resolve(root);
    const resolvedTarget = resolve(target);
    const delta = relative(resolvedRoot, resolvedTarget);
    if (
      !delta ||
      isAbsolute(delta) ||
      delta === '..' ||
      delta.startsWith(`..${sep}`) ||
      resolve(resolvedRoot, delta) !== resolvedTarget
    ) {
      throw new BadRequestException(`${label} must be a strict descendant of the scratch root.`);
    }
  }

  private assertDisjointPaths(first: string, second: string): void {
    const resolvedFirst = resolve(first);
    const resolvedSecond = resolve(second);
    const firstToSecond = relative(resolvedFirst, resolvedSecond);
    const secondToFirst = relative(resolvedSecond, resolvedFirst);
    const isNested = (delta: string) =>
      delta !== '' && delta !== '..' && !delta.startsWith(`..${sep}`);
    if (
      resolvedFirst === resolvedSecond ||
      isNested(firstToSecond) ||
      isNested(secondToFirst)
    ) {
      throw new BadRequestException(
        'Repository workspace and credential tmpfs paths must be disjoint.'
      );
    }
  }

  private async assertRealDescendant(
    root: string,
    target: string,
    label: string
  ): Promise<void> {
    const [realRoot, realTarget] = await Promise.all([
      this.assertRealDirectory(root, `${label} root`),
      this.assertRealDirectory(target, label)
    ]);
    this.assertDescendant(realRoot, realTarget, label);
  }

  private async assertRealDirectory(path: string, label: string): Promise<string> {
    const resolvedPath = resolve(path);
    const stats = await lstat(resolvedPath).catch(() => null);
    if (!stats || !stats.isDirectory() || stats.isSymbolicLink()) {
      throw new BadRequestException(`${label} must be a real directory.`);
    }
    return realpath(resolvedPath);
  }

  private async ensureRealDirectoryPath(
    root: string,
    target: string,
    label: string
  ): Promise<void> {
    const resolvedRoot = resolve(root);
    const resolvedTarget = resolve(target);
    const delta = relative(resolvedRoot, resolvedTarget);
    if (delta === '') {
      await this.assertRealDirectory(resolvedRoot, label);
      return;
    }
    if (isAbsolute(delta) || delta === '..' || delta.startsWith(`..${sep}`)) {
      throw new BadRequestException(`${label} must remain inside the scratch root.`);
    }

    const realRoot = await this.assertRealDirectory(resolvedRoot, `${label} root`);
    let cursor = resolvedRoot;
    for (const segment of delta.split(sep)) {
      cursor = join(cursor, segment);
      try {
        await mkdir(cursor, { recursive: false, mode: 0o700 });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
          throw error;
        }
      }
      const realCursor = await this.assertRealDirectory(cursor, label);
      this.assertDescendant(realRoot, realCursor, label);
    }
  }
}

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}
