import { createHash } from 'node:crypto';
import type { PeerCertificate } from 'node:tls';

import { Injectable } from '@nestjs/common';
import type { Request } from 'express';

export interface AuthenticatedSastWorkloadIdentity {
  identityRef: string;
  certificateFingerprint: `sha256:${string}`;
}

interface MtlsSocket {
  encrypted?: boolean;
  authorized?: boolean;
  getPeerCertificate?: (detailed?: boolean) => PeerCertificate;
}

export abstract class SastWorkloadIdentityAuthenticator {
  abstract authenticate(
    request: Request
  ): Promise<AuthenticatedSastWorkloadIdentity | null>;
}

@Injectable()
export class DirectMtlsSastWorkloadIdentityAuthenticator
  extends SastWorkloadIdentityAuthenticator
{
  authenticate(
    request: Request
  ): Promise<AuthenticatedSastWorkloadIdentity | null> {
    const socket = request.socket as MtlsSocket;
    if (
      socket.encrypted !== true ||
      socket.authorized !== true ||
      typeof socket.getPeerCertificate !== 'function'
    ) {
      return Promise.resolve(null);
    }

    const certificate = socket.getPeerCertificate(false);
    if (
      !certificate?.raw ||
      !this.isCertificateCurrentlyValid(certificate) ||
      typeof certificate.subjectaltname !== 'string'
    ) {
      return Promise.resolve(null);
    }

    const identityRef = this.extractSingleSpiffeUri(
      certificate.subjectaltname
    );
    if (!identityRef) {
      return Promise.resolve(null);
    }

    return Promise.resolve({
      identityRef,
      certificateFingerprint: `sha256:${createHash('sha256')
        .update(certificate.raw)
        .digest('hex')}`
    });
  }

  private extractSingleSpiffeUri(subjectAlternativeName: string): string | null {
    const uriEntries = subjectAlternativeName
      .split(/,\s*/u)
      .filter((entry) => entry.startsWith('URI:'))
      .map((entry) => entry.slice(4));

    if (uriEntries.length !== 1) {
      return null;
    }

    const identityRef = uriEntries[0];
    const spiffeId =
      /^spiffe:\/\/([a-z0-9](?:[a-z0-9._-]{0,254}))((?:\/[A-Za-z0-9._-]+)+)$/u.exec(
        identityRef
      );
    if (
      identityRef.length === 0 ||
      Buffer.byteLength(identityRef, 'utf8') > 512 ||
      identityRef !== identityRef.trim() ||
      identityRef !== identityRef.normalize('NFC') ||
      !spiffeId ||
      spiffeId[2]
        .slice(1)
        .split('/')
        .some((segment) => segment === '.' || segment === '..')
    ) {
      return null;
    }

    return identityRef;
  }

  private isCertificateCurrentlyValid(certificate: PeerCertificate): boolean {
    const validFrom = Date.parse(certificate.valid_from);
    const validTo = Date.parse(certificate.valid_to);
    const now = Date.now();

    return (
      Number.isFinite(validFrom) &&
      Number.isFinite(validTo) &&
      validFrom <= now &&
      now < validTo
    );
  }
}
