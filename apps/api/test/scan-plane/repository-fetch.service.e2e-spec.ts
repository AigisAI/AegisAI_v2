import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import type { TokenBrokerIssueRequest } from '@aegisai/shared';

import {
  RepositoryGitExecutor,
  type RepositoryGitCommand,
  type RepositoryGitCommandResult
} from '../../src/scan-plane/repository-git-executor';
import { RepositoryFetchService } from '../../src/scan-plane/repository-fetch.service';
import type { CredentialTmpfsVerifier } from '../../src/scan-plane/credential-tmpfs-verifier.service';
import type { TokenBrokerService } from '../../src/token-broker/token-broker.service';
import type { ControlPlaneService } from '../../src/control-plane/control-plane.service';

class RecordingGitExecutor extends RepositoryGitExecutor {
  readonly commands: RepositoryGitCommand[] = [];

  constructor(
    private readonly commitSha: string,
    private readonly workspaceRoot: string,
    private readonly treeOutput?: string
  ) {
    super();
  }

  async run(command: RepositoryGitCommand): Promise<RepositoryGitCommandResult> {
    this.commands.push(command);
    const args = command.args.join(' ');
    if (args === 'init --quiet .') {
      await mkdir(join(this.workspaceRoot, '.git'), { recursive: true });
      await writeFile(join(this.workspaceRoot, '.git', 'config'), '[core]\n');
    }
    if (args.startsWith('checkout ')) {
      await mkdir(join(this.workspaceRoot, 'src'), { recursive: true });
      await mkdir(join(this.workspaceRoot, 'assets'), { recursive: true });
      await writeFile(join(this.workspaceRoot, 'src', 'App.java'), 'class App {}');
      await writeFile(
        join(this.workspaceRoot, 'assets', 'large.bin'),
        [
          'version https://git-lfs.github.com/spec/v1',
          `oid sha256:${'f'.repeat(64)}`,
          'size 1000000',
          ''
        ].join('\n')
      );
    }
    if (args === 'rev-parse FETCH_HEAD^{commit}' || args === 'rev-parse HEAD') {
      return this.output(`${this.commitSha}\n`);
    }
    if (args === 'rev-parse --is-shallow-repository') {
      return this.output('true\n');
    }
    if (args === 'ls-tree -r -z -l HEAD') {
      const tree =
        this.treeOutput ??
        [
          `100644 blob ${'1'.repeat(40)}      12\tsrc/App.java\0`,
          `100644 blob ${'2'.repeat(40)}     130\tassets/large.bin\0`
        ].join('');
      return { stdout: Buffer.from(tree), stderr: Buffer.alloc(0) };
    }
    if (args === 'count-objects -v') {
      return this.output('count: 2\nsize: 4\nin-pack: 5\nsize-pack: 8\n');
    }
    return this.output('');
  }

  private output(stdout: string): RepositoryGitCommandResult {
    return { stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) };
  }
}

describe('RepositoryFetchService', () => {
  const commitSha = 'a'.repeat(40);
  let scratchRoot: string;
  let workspaceRoot: string;
  let credentialTmpfsRoot: string;

  beforeEach(async () => {
    scratchRoot = await mkdtemp(join(tmpdir(), 'aegis-fetch-test-'));
    workspaceRoot = join(scratchRoot, 'workspace');
    credentialTmpfsRoot = join(scratchRoot, 'credential-tmpfs');
  });

  afterEach(async () => {
    await rm(scratchRoot, { recursive: true, force: true });
  });

  const tokenRequest = (): TokenBrokerIssueRequest => {
    const scope = {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      attemptId: 'attempt-1',
      workloadIdentityRef: 'spiffe://aegisai/scan/attempt-1',
      commitSha
    };
    return {
      ...scope,
      workloadIdentityAttestation: {
        claims: {
          version: '1',
          issuer: 'aegisai-sandbox-provisioner',
          audience: 'aegisai-token-broker',
          ...scope,
          nonce: 'nonce-1',
          issuedAt: '2026-07-24T00:00:00.000Z',
          expiresAt: '2026-07-24T00:02:00.000Z'
        },
        signature: `sha256:${'c'.repeat(64)}`
      },
      principal: 'REPO_READ',
      ttlSeconds: 120,
      auditReason: 'fixed-commit-fetch'
    };
  };

  it('uses one fixed SHA with shallow fetch while keeping the credential out of argv and env', async () => {
    const secret = 'repository-secret-value';
    let credentialAfterUse: Uint8Array | undefined;
    const tokenBroker = {
      withCredential: jest.fn(
        async (
          _request: TokenBrokerIssueRequest,
          consumer: (credential: Uint8Array) => Promise<unknown>
        ) => {
          const credential = Buffer.from(secret);
          credentialAfterUse = credential;
          try {
            return await consumer(credential);
          } finally {
            credential.fill(0);
          }
        }
      )
    } as unknown as TokenBrokerService;
    const executor = new RecordingGitExecutor(commitSha, workspaceRoot);
    const service = new RepositoryFetchService(
      tokenBroker,
      executor,
      {
        getRepositoryFetchTarget: jest.fn().mockResolvedValue({
          provider: 'GITHUB',
          fullName: 'acme/service'
        })
      } as unknown as ControlPlaneService,
      { assertTmpfs: jest.fn() } as unknown as CredentialTmpfsVerifier
    );

    const result = await service.fetch({
      scratchRoot,
      workspaceRoot,
      credentialTmpfsRoot,
      tokenRequest: tokenRequest()
    });

    expect(result.metadata).toEqual({
      attemptId: 'attempt-1',
      fixedCommitSha: commitSha,
      remoteHost: 'github.com',
      objectCount: 7,
      fetchedBytes: 12 * 1024,
      shallow: true,
      detachedHead: true,
      submodulesFetched: false,
      lfsObjectsFetched: false,
      archivesExpanded: false,
      gitMetadataRemoved: true,
      credentialWiped: true
    });
    expect(result.entries).toEqual([
      expect.objectContaining({ path: 'src/App.java', lfsPointer: false }),
      expect.objectContaining({ path: 'assets/large.bin', lfsPointer: true })
    ]);
    expect(
      executor.commands.map((command) => command.args).find((args) => args[0] === 'fetch')
    ).toEqual([
      'fetch',
      '--quiet',
      '--no-tags',
      '--depth=1',
      '--no-recurse-submodules',
      'origin',
      commitSha
    ]);
    expect(
      executor.commands
        .map((command) => command.args)
        .filter((args) => args[0] === 'remote')
    ).toEqual([
      ['remote', 'add', 'origin', 'https://github.com/acme/service.git'],
      ['remote', 'remove', 'origin']
    ]);
    expect(
      JSON.stringify(
        executor.commands.map((command) => ({
          args: command.args,
          environment: command.environment
        }))
      )
    ).not.toContain(secret);
    expect(
      executor.commands.some((command) =>
        command.args.some((argument) => /refs\/heads|refs\/tags|main|master/.test(argument))
      )
    ).toBe(false);
    expect(credentialAfterUse && [...credentialAfterUse].every((value) => value === 0)).toBe(true);
    expect(await readdir(credentialTmpfsRoot)).toEqual([]);
    expect(await readdir(workspaceRoot)).not.toContain('.git');
  });

  it('rejects invalid durable repository names and non-fixed commit identifiers', async () => {
    const service = new RepositoryFetchService(
      { withCredential: jest.fn() } as unknown as TokenBrokerService,
      new RecordingGitExecutor(commitSha, workspaceRoot),
      {
        getRepositoryFetchTarget: jest.fn().mockResolvedValue({
          provider: 'GITHUB',
          fullName: 'https://evil.example/repository'
        })
      } as unknown as ControlPlaneService,
      { assertTmpfs: jest.fn() } as unknown as CredentialTmpfsVerifier
    );
    const base = {
      scratchRoot,
      workspaceRoot,
      credentialTmpfsRoot,
      tokenRequest: tokenRequest()
    };

    await expect(service.fetch(base)).rejects.toThrow('repository name');

    const validTargetService = new RepositoryFetchService(
      { withCredential: jest.fn() } as unknown as TokenBrokerService,
      new RecordingGitExecutor(commitSha, workspaceRoot),
      {
        getRepositoryFetchTarget: jest.fn().mockResolvedValue({
          provider: 'GITHUB',
          fullName: 'acme/service'
        })
      } as unknown as ControlPlaneService,
      { assertTmpfs: jest.fn() } as unknown as CredentialTmpfsVerifier
    );
    await expect(
      validTargetService.fetch({
        ...base,
        tokenRequest: { ...tokenRequest(), commitSha: 'main' }
      })
    ).rejects.toThrow('full fixed commit');

    await expect(
      validTargetService.fetch({
        ...base,
        credentialTmpfsRoot: join(workspaceRoot, 'credentials')
      })
    ).rejects.toThrow('must be disjoint');
  });

  it('rejects Git tree entry modes outside the regular-file, symlink, and submodule policy', async () => {
    const tokenBroker = {
      withCredential: jest.fn(
        async (
          _request: TokenBrokerIssueRequest,
          consumer: (credential: Uint8Array) => Promise<unknown>
        ) => {
          const credential = Buffer.from('repository-secret-value');
          try {
            return await consumer(credential);
          } finally {
            credential.fill(0);
          }
        }
      )
    } as unknown as TokenBrokerService;
    const invalidTree = `060000 blob ${'1'.repeat(40)}      12\tsrc/App.java\0`;
    const service = new RepositoryFetchService(
      tokenBroker,
      new RecordingGitExecutor(commitSha, workspaceRoot, invalidTree),
      {
        getRepositoryFetchTarget: jest.fn().mockResolvedValue({
          provider: 'GITHUB',
          fullName: 'acme/service'
        })
      } as unknown as ControlPlaneService,
      { assertTmpfs: jest.fn() } as unknown as CredentialTmpfsVerifier
    );

    await expect(
      service.fetch({
        scratchRoot,
        workspaceRoot,
        credentialTmpfsRoot,
        tokenRequest: tokenRequest()
      })
    ).rejects.toThrow('entry type or size');
    expect(await readdir(credentialTmpfsRoot)).toEqual([]);
  });
});
