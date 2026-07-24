import { statfs } from 'node:fs/promises';

import { Injectable, ServiceUnavailableException } from '@nestjs/common';

const TMPFS_MAGIC = 0x01021994;

export abstract class CredentialTmpfsVerifier {
  abstract assertTmpfs(path: string): Promise<void>;
}

@Injectable()
export class NodeCredentialTmpfsVerifier extends CredentialTmpfsVerifier {
  async assertTmpfs(path: string): Promise<void> {
    const stats = await statfs(path);
    if (Number(stats.type) !== TMPFS_MAGIC) {
      throw new ServiceUnavailableException(
        'Repository credential handoff requires a verified tmpfs mount.'
      );
    }
  }
}
