import { spawn } from 'node:child_process';

import { Injectable } from '@nestjs/common';

export interface RepositoryGitCommand {
  args: string[];
  cwd: string;
  environment: Record<string, string>;
  timeoutMilliseconds: number;
  maxOutputBytes?: number;
}

export interface RepositoryGitCommandResult {
  stdout: Buffer;
  stderr: Buffer;
}

export abstract class RepositoryGitExecutor {
  abstract run(command: RepositoryGitCommand): Promise<RepositoryGitCommandResult>;
}

@Injectable()
export class NodeRepositoryGitExecutor extends RepositoryGitExecutor {
  run(command: RepositoryGitCommand): Promise<RepositoryGitCommandResult> {
    const maxOutputBytes = command.maxOutputBytes ?? 32 * 1024 * 1024;
    return new Promise((resolve, reject) => {
      const child = spawn('git', command.args, {
        cwd: command.cwd,
        env: this.buildEnvironment(command.environment),
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let outputBytes = 0;
      let settled = false;
      let timeout: NodeJS.Timeout | undefined = undefined;

      const finish = (error?: Error) => {
        if (settled) {
          return;
        }
        settled = true;
        if (timeout) {
          clearTimeout(timeout);
        }
        if (error) {
          reject(error);
          return;
        }
        resolve({
          stdout: Buffer.concat(stdout),
          stderr: Buffer.concat(stderr)
        });
      };

      const append = (target: Buffer[], chunk: Buffer) => {
        if (settled) {
          return;
        }
        outputBytes += chunk.length;
        if (outputBytes > maxOutputBytes) {
          child.kill('SIGKILL');
          finish(new Error('Git command output exceeded the bounded runtime limit.'));
          return;
        }
        target.push(chunk);
      };

      child.stdout.on('data', (chunk: Buffer) => append(stdout, chunk));
      child.stderr.on('data', (chunk: Buffer) => append(stderr, chunk));
      child.on('error', (error) => finish(error));
      child.on('close', (code, signal) => {
        if (code !== 0) {
          finish(
            new Error(
              `Git command failed with exit code ${String(code)} and signal ${String(signal)}.`
            )
          );
          return;
        }
        finish();
      });

      timeout = setTimeout(() => {
        child.kill('SIGKILL');
        finish(new Error('Git command exceeded the bounded runtime timeout.'));
      }, command.timeoutMilliseconds);
      timeout.unref();
    });
  }

  private buildEnvironment(environment: Record<string, string>): NodeJS.ProcessEnv {
    const base: NodeJS.ProcessEnv = {};
    for (const key of ['PATH', 'SystemRoot', 'WINDIR']) {
      if (process.env[key]) {
        base[key] = process.env[key];
      }
    }
    return { ...base, ...environment };
  }
}
