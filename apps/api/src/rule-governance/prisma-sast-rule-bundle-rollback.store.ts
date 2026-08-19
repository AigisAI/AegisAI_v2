import {
  isSastRuleBundleRollbackApprovalValid,
  isSastRuleBundleRollbackCommandValid,
  isSastRuleBundleRollbackReceiptValid,
  isSastRuleBundleRollbackVerificationValid,
  type SastRuleBundlePromotionApprovalRole,
  type SastRuleBundleRollbackActorRole,
  type SastRuleBundleRollbackApproval,
  type SastRuleBundleRollbackApprovalBinding,
  type SastRuleBundleRollbackCommand,
  type SastRuleBundleRollbackReceipt,
  type SastRuleBundleRollbackVerification,
  type SastProfileId
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import { runSastKillSwitchSerializable } from './sast-kill-switch-persistence';
import {
  SastRuleBundleRollbackPersistenceError,
  SastRuleBundleRollbackStore,
  type PersistedSastRuleBundleRollbackApproval,
  type PersistedSastRuleBundleRollbackCommand,
  type PersistedSastRuleBundleRollbackReceipt,
  type SastRuleBundleRollbackCommandSnapshot
} from './sast-rule-bundle-rollback.store';

type CommandRow =
  Prisma.SastRuleBundleRollbackCommandGetPayload<Record<string, never>>;
type VerificationRow =
  Prisma.SastRuleBundleRollbackVerificationGetPayload<Record<string, never>>;
type ApprovalRow =
  Prisma.SastRuleBundleRollbackApprovalGetPayload<Record<string, never>>;
type ReceiptRow =
  Prisma.SastRuleBundleRollbackReceiptGetPayload<Record<string, never>>;
type ReceiptApprovalRow =
  Prisma.SastRuleBundleRollbackReceiptApprovalGetPayload<Record<string, never>>;

@Injectable()
export class PrismaSastRuleBundleRollbackStore extends SastRuleBundleRollbackStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async registerCommand(input: {
    command: Readonly<SastRuleBundleRollbackCommand>;
    verification: Readonly<SastRuleBundleRollbackVerification>;
  }): Promise<PersistedSastRuleBundleRollbackCommand> {
    assertCommandValid(input.command);
    assertVerificationValid(input.verification);
    if (!verificationMatchesCommand(input.verification, input.command)) {
      throw persistenceError('INPUT_INVALID');
    }

    const persist = () =>
      this.runSerializable(async (tx) => {
        await lockLifecycleHeads(tx, [
          input.command.candidateManifestId,
          input.command.baselineManifestId
        ]);
        const existing =
          (await tx.sastRuleBundleRollbackCommand.findUnique({
            where: { id: input.command.commandId }
          })) ??
          (await tx.sastRuleBundleRollbackCommand.findUnique({
            where: {
              candidateManifestId: input.command.candidateManifestId
            }
          }));
        if (existing) {
          const verification =
            await tx.sastRuleBundleRollbackVerification.findUnique({
              where: { commandId: existing.id }
            });
          return replayCommand(
            existing,
            verification,
            input.command,
            input.verification
          );
        }

        const command = await tx.sastRuleBundleRollbackCommand.create({
          data: commandData(input.command)
        });
        const verification =
          await tx.sastRuleBundleRollbackVerification.create({
            data: verificationData(input.verification)
          });
        return replayCommand(
          command,
          verification,
          input.command,
          input.verification,
          false
        );
      });
    try {
      return await persist();
    } catch (error) {
      if (isUniqueConflict(error)) {
        try {
          return await persist();
        } catch (replayError) {
          throw toPersistenceError(replayError);
        }
      }
      throw toPersistenceError(error);
    }
  }

  async findCommandForCandidate(
    manifestId: string
  ): Promise<SastRuleBundleRollbackCommandSnapshot | null> {
    try {
      const row = await this.prisma.sastRuleBundleRollbackCommand.findUnique({
        where: { candidateManifestId: manifestId }
      });
      return row ? await this.snapshot(this.prisma, row) : null;
    } catch (error) {
      throw toPersistenceError(error);
    }
  }

  async findCommand(
    commandId: string
  ): Promise<SastRuleBundleRollbackCommandSnapshot | null> {
    try {
      const row = await this.prisma.sastRuleBundleRollbackCommand.findUnique({
        where: { id: commandId }
      });
      return row ? await this.snapshot(this.prisma, row) : null;
    } catch (error) {
      throw toPersistenceError(error);
    }
  }

  async registerApproval(
    approval: Readonly<SastRuleBundleRollbackApproval>
  ): Promise<PersistedSastRuleBundleRollbackApproval> {
    assertApprovalValid(approval);
    const persist = () =>
      this.runSerializable(async (tx) => {
        const [command] = await tx.$queryRaw<CommandRow[]>(Prisma.sql`
          SELECT * FROM "SastRuleBundleRollbackCommand"
          WHERE "id" = ${approval.commandId}
          FOR UPDATE
        `);
        if (!command) throw persistenceError('COMMAND_NOT_FOUND');
        if (command.commandDigest !== approval.commandDigest) {
          throw persistenceError('INPUT_INVALID');
        }
        const existing =
          (await tx.sastRuleBundleRollbackApproval.findUnique({
            where: { id: approval.approvalId }
          })) ??
          (await tx.sastRuleBundleRollbackApproval.findUnique({
            where: {
              commandId_role: {
                commandId: approval.commandId,
                role: approval.role
              }
            }
          }));
        if (existing) return replayApproval(existing, approval);
        const created = await tx.sastRuleBundleRollbackApproval.create({
          data: approvalData(approval)
        });
        return replayApproval(created, approval, false);
      });
    try {
      return await persist();
    } catch (error) {
      if (isUniqueConflict(error)) {
        try {
          return await persist();
        } catch (replayError) {
          throw toPersistenceError(replayError);
        }
      }
      throw toPersistenceError(error);
    }
  }

  async registerReceipt(
    receipt: Readonly<SastRuleBundleRollbackReceipt>
  ): Promise<PersistedSastRuleBundleRollbackReceipt> {
    assertReceiptValid(receipt);
    const persist = () =>
      this.runSerializable(async (tx) => {
        await lockLifecycleHeads(tx, [
          receipt.candidateManifestId,
          receipt.baselineManifestId
        ]);
        const existing =
          (await tx.sastRuleBundleRollbackReceipt.findUnique({
            where: { id: receipt.receiptRef }
          })) ??
          (await tx.sastRuleBundleRollbackReceipt.findUnique({
            where: { commandId: receipt.commandId }
          }));
        if (existing) {
          const approvals =
            await tx.sastRuleBundleRollbackReceiptApproval.findMany({
              where: { receiptId: existing.id },
              orderBy: { position: 'asc' }
            });
          return replayReceipt(existing, approvals, receipt);
        }

        const command = await tx.sastRuleBundleRollbackCommand.findUnique({
          where: { id: receipt.commandId },
          select: { commandDigest: true }
        });
        if (!command) throw persistenceError('COMMAND_NOT_FOUND');
        if (command.commandDigest !== receipt.commandDigest) {
          throw persistenceError('INPUT_INVALID');
        }
        const created = await tx.sastRuleBundleRollbackReceipt.create({
          data: receiptData(receipt)
        });
        await tx.sastRuleBundleRollbackReceiptApproval.createMany({
          data: receipt.approvals.map((approval, position) => ({
            receiptId: receipt.receiptRef,
            position,
            approvalId: approval.approvalId,
            approvalDigest: approval.approvalDigest,
            commandId: receipt.commandId,
            commandDigest: receipt.commandDigest,
            role: approval.role,
            approverRef: approval.approverRef,
            approvedAt: new Date(approval.approvedAt)
          }))
        });
        const approvals =
          await tx.sastRuleBundleRollbackReceiptApproval.findMany({
            where: { receiptId: created.id },
            orderBy: { position: 'asc' }
          });
        return replayReceipt(created, approvals, receipt, false);
      });
    try {
      return await persist();
    } catch (error) {
      if (isUniqueConflict(error)) {
        try {
          return await persist();
        } catch (replayError) {
          throw toPersistenceError(replayError);
        }
      }
      throw toPersistenceError(error);
    }
  }

  private async snapshot(
    client: Pick<PrismaService, 'sastRuleBundleRollbackVerification' | 'sastRuleBundleRollbackApproval' | 'sastRuleBundleRollbackReceipt' | 'sastRuleBundleRollbackReceiptApproval'>,
    row: Readonly<CommandRow>
  ): Promise<SastRuleBundleRollbackCommandSnapshot> {
    const [verification, approvalRows, receiptRow] = await Promise.all([
      client.sastRuleBundleRollbackVerification.findUnique({
        where: { commandId: row.id }
      }),
      client.sastRuleBundleRollbackApproval.findMany({
        where: { commandId: row.id }
      }),
      client.sastRuleBundleRollbackReceipt.findUnique({
        where: { commandId: row.id }
      })
    ]);
    if (!verification) throw persistenceError('VERIFICATION_NOT_FOUND');
    const approvals = approvalRows
      .map(approvalFromRow)
      .sort((left, right) => roleOrder(left.role) - roleOrder(right.role));
    let receipt: SastRuleBundleRollbackReceipt | null = null;
    if (receiptRow) {
      const bindings =
        await client.sastRuleBundleRollbackReceiptApproval.findMany({
          where: { receiptId: receiptRow.id },
          orderBy: { position: 'asc' }
        });
      receipt = receiptFromRow(receiptRow, bindings);
      assertReceiptValid(receipt, 'LEDGER_CORRUPT');
    }
    const command = commandFromRow(row);
    const mappedVerification = verificationFromRow(verification);
    assertCommandValid(command, 'LEDGER_CORRUPT');
    assertVerificationValid(mappedVerification, 'LEDGER_CORRUPT');
    approvals.forEach((approval) => assertApprovalValid(approval, 'LEDGER_CORRUPT'));
    return { command, verification: mappedVerification, approvals, receipt };
  }

  private runSerializable<T>(
    operation: (tx: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    return runSastKillSwitchSerializable(this.prisma, operation);
  }
}

async function lockLifecycleHeads(
  tx: Prisma.TransactionClient,
  manifestIds: readonly string[]
): Promise<void> {
  const ordered = [...new Set(manifestIds)].sort(compareText);
  if (ordered.length !== 2) throw persistenceError('INPUT_INVALID');
  const rows = await tx.$queryRaw<Array<{ manifestId: string }>>(Prisma.sql`
    SELECT "manifestId"
    FROM "SastRuleBundleLifecycleHead"
    WHERE "manifestId" IN (${Prisma.join(ordered)})
    ORDER BY "manifestId" COLLATE "C"
    FOR UPDATE
  `);
  if (
    rows.length !== ordered.length ||
    rows.some((row, index) => row.manifestId !== ordered[index])
  ) {
    throw persistenceError('STATE_STALE');
  }
}

function replayCommand(
  commandRow: Readonly<CommandRow>,
  verificationRow: Readonly<VerificationRow> | null,
  expectedCommand: Readonly<SastRuleBundleRollbackCommand>,
  expectedVerification: Readonly<SastRuleBundleRollbackVerification>,
  replayed = true
): PersistedSastRuleBundleRollbackCommand {
  if (!verificationRow) throw persistenceError('VERIFICATION_NOT_FOUND');
  const command = commandFromRow(commandRow);
  const verification = verificationFromRow(verificationRow);
  assertCommandValid(command, 'LEDGER_CORRUPT');
  assertVerificationValid(verification, 'LEDGER_CORRUPT');
  if (
    command.commandId !== expectedCommand.commandId ||
    command.commandDigest !== expectedCommand.commandDigest ||
    verification.verificationId !== expectedVerification.verificationId ||
    verification.verificationDigest !== expectedVerification.verificationDigest
  ) {
    throw persistenceError('REPLAY_CONFLICT');
  }
  return { command, verification, replayed };
}

function replayApproval(
  row: Readonly<ApprovalRow>,
  expected: Readonly<SastRuleBundleRollbackApproval>,
  replayed = true
): PersistedSastRuleBundleRollbackApproval {
  const approval = approvalFromRow(row);
  assertApprovalValid(approval, 'LEDGER_CORRUPT');
  if (
    approval.approvalId !== expected.approvalId ||
    approval.approvalDigest !== expected.approvalDigest
  ) {
    throw persistenceError('REPLAY_CONFLICT');
  }
  return { approval, replayed };
}

function replayReceipt(
  row: Readonly<ReceiptRow>,
  approvalRows: readonly Readonly<ReceiptApprovalRow>[],
  expected: Readonly<SastRuleBundleRollbackReceipt>,
  replayed = true
): PersistedSastRuleBundleRollbackReceipt {
  const receipt = receiptFromRow(row, approvalRows);
  assertReceiptValid(receipt, 'LEDGER_CORRUPT');
  if (
    receipt.receiptRef !== expected.receiptRef ||
    receipt.receiptDigest !== expected.receiptDigest
  ) {
    throw persistenceError('REPLAY_CONFLICT');
  }
  return { receipt, replayed };
}

function commandData(command: Readonly<SastRuleBundleRollbackCommand>) {
  return {
    id: command.commandId,
    contractVersion: command.version,
    commandDigest: command.commandDigest,
    candidateManifestId: command.candidateManifestId,
    candidateManifestDigest: command.candidateManifestDigest,
    candidateVerificationId: command.candidateVerificationId,
    candidateVerificationDigest: command.candidateVerificationDigest,
    candidateBundleId: command.candidateBundleId,
    candidateBundleDigest: command.candidateBundleDigest,
    suspendedTransitionId: command.suspendedTransitionId,
    suspendedTransitionDigest: command.suspendedTransitionDigest,
    suspendedSequence: command.suspendedSequence,
    suspendedTransitionedAt: new Date(command.suspendedTransitionedAt),
    suspensionAuthorityReceiptRef: command.suspensionAuthorityReceiptRef,
    suspensionAuthorityReceiptDigest:
      command.suspensionAuthorityReceiptDigest,
    promotionEvidenceId: command.promotionEvidenceId,
    promotionEvidenceDigest: command.promotionEvidenceDigest,
    profileId: command.profileId,
    baselineManifestId: command.baselineManifestId,
    baselineManifestDigest: command.baselineManifestDigest,
    baselineVerificationId: command.baselineVerificationId,
    baselineVerificationDigest: command.baselineVerificationDigest,
    baselineBundleId: command.baselineBundleId,
    baselineBundleDigest: command.baselineBundleDigest,
    baselineTransitionId: command.baselineTransitionId,
    baselineTransitionDigest: command.baselineTransitionDigest,
    baselineSequence: command.baselineSequence,
    baselineTransitionedAt: new Date(command.baselineTransitionedAt),
    baselineState: command.baselineState,
    incidentRef: command.incidentRef,
    actorRef: command.actorRef,
    actorRole: command.actorRole,
    reasonRef: command.reasonRef,
    auditRef: command.auditRef,
    signatureRef: command.signatureRef,
    provenanceRef: command.provenanceRef,
    commandedAt: new Date(command.commandedAt),
    rollbackTargetDerived: command.rollbackTargetDerived,
    customerTargetAccepted: command.customerTargetAccepted,
    source: command.source,
    immutable: command.immutable,
    repositoryContentStored: command.repositoryContentStored,
    findingContentStored: command.findingContentStored,
    secretValueStored: command.secretValueStored,
    arbitraryPayloadStored: command.arbitraryPayloadStored
  };
}

function verificationData(
  verification: Readonly<SastRuleBundleRollbackVerification>
) {
  return {
    id: verification.verificationId,
    contractVersion: verification.version,
    verificationDigest: verification.verificationDigest,
    commandId: verification.commandId,
    commandDigest: verification.commandDigest,
    signerIdentity: verification.signerIdentity,
    signatureRef: verification.signatureRef,
    provenanceRef: verification.provenanceRef,
    verifiedAt: new Date(verification.verifiedAt),
    signatureVerified: verification.signatureVerified,
    provenanceVerified: verification.provenanceVerified,
    trustedSigner: verification.trustedSigner,
    signatureBytesStored: verification.signatureBytesStored,
    provenancePayloadStored: verification.provenancePayloadStored,
    repositoryContentStored: verification.repositoryContentStored,
    secretValueStored: verification.secretValueStored
  };
}

function approvalData(approval: Readonly<SastRuleBundleRollbackApproval>) {
  return {
    id: approval.approvalId,
    contractVersion: approval.version,
    approvalDigest: approval.approvalDigest,
    commandId: approval.commandId,
    commandDigest: approval.commandDigest,
    role: approval.role,
    approverRef: approval.approverRef,
    approvalRef: approval.approvalRef,
    approvedAt: new Date(approval.approvedAt),
    approved: approval.approved,
    humanApproval: approval.humanApproval,
    automatedApproval: approval.automatedApproval,
    customerInputAccepted: approval.customerInputAccepted
  };
}

function receiptData(receipt: Readonly<SastRuleBundleRollbackReceipt>) {
  return {
    id: receipt.receiptRef,
    contractVersion: receipt.version,
    receiptDigest: receipt.receiptDigest,
    commandId: receipt.commandId,
    commandDigest: receipt.commandDigest,
    commandVerificationId: receipt.commandVerificationId,
    commandVerificationDigest: receipt.commandVerificationDigest,
    candidateManifestId: receipt.candidateManifestId,
    candidateManifestDigest: receipt.candidateManifestDigest,
    candidateBundleId: receipt.candidateBundleId,
    candidateBundleDigest: receipt.candidateBundleDigest,
    suspendedTransitionId: receipt.suspendedTransitionId,
    suspendedTransitionDigest: receipt.suspendedTransitionDigest,
    suspendedSequence: receipt.suspendedSequence,
    suspendedTransitionedAt: new Date(receipt.suspendedTransitionedAt),
    suspensionAuthorityReceiptRef: receipt.suspensionAuthorityReceiptRef,
    suspensionAuthorityReceiptDigest:
      receipt.suspensionAuthorityReceiptDigest,
    promotionEvidenceId: receipt.promotionEvidenceId,
    promotionEvidenceDigest: receipt.promotionEvidenceDigest,
    profileId: receipt.profileId,
    baselineManifestId: receipt.baselineManifestId,
    baselineManifestDigest: receipt.baselineManifestDigest,
    baselineVerificationId: receipt.baselineVerificationId,
    baselineVerificationDigest: receipt.baselineVerificationDigest,
    baselineBundleId: receipt.baselineBundleId,
    baselineBundleDigest: receipt.baselineBundleDigest,
    baselineTransitionId: receipt.baselineTransitionId,
    baselineTransitionDigest: receipt.baselineTransitionDigest,
    baselineSequence: receipt.baselineSequence,
    baselineTransitionedAt: new Date(receipt.baselineTransitionedAt),
    baselineState: receipt.baselineState,
    approvalCount: receipt.approvalCount,
    approvalSetDigest: receipt.approvalSetDigest,
    actorRef: receipt.actorRef,
    reasonRef: receipt.reasonRef,
    auditRef: receipt.auditRef,
    commandedAt: new Date(receipt.commandedAt),
    requestedAt: new Date(receipt.requestedAt),
    issuedAt: new Date(receipt.issuedAt),
    fromState: receipt.fromState,
    toState: receipt.toState,
    rollbackTargetDerived: receipt.rollbackTargetDerived,
    baselineMutationAuthorized: receipt.baselineMutationAuthorized,
    historicalMutationAuthorized: receipt.historicalMutationAuthorized,
    scannerSetMutationAuthorized: receipt.scannerSetMutationAuthorized,
    findingAuthority: receipt.findingAuthority,
    policyAuthority: receipt.policyAuthority,
    publicationAuthority: receipt.publicationAuthority,
    scmWriteAuthority: receipt.scmWriteAuthority,
    customerInputAccepted: receipt.customerInputAccepted,
    repositoryContentStored: receipt.repositoryContentStored,
    findingContentStored: receipt.findingContentStored,
    secretValueStored: receipt.secretValueStored,
    arbitraryPayloadStored: receipt.arbitraryPayloadStored
  };
}

function commandFromRow(row: Readonly<CommandRow>): SastRuleBundleRollbackCommand {
  return {
    version: 'sast-rule-bundle-rollback-command-v1',
    commandId: row.id,
    commandDigest: asDigest(row.commandDigest),
    candidateManifestId: row.candidateManifestId,
    candidateManifestDigest: asDigest(row.candidateManifestDigest),
    candidateVerificationId: row.candidateVerificationId,
    candidateVerificationDigest: asDigest(row.candidateVerificationDigest),
    candidateBundleId: row.candidateBundleId,
    candidateBundleDigest: asDigest(row.candidateBundleDigest),
    suspendedTransitionId: row.suspendedTransitionId,
    suspendedTransitionDigest: asDigest(row.suspendedTransitionDigest),
    suspendedSequence: row.suspendedSequence,
    suspendedTransitionedAt: row.suspendedTransitionedAt.toISOString(),
    suspensionAuthorityReceiptRef: row.suspensionAuthorityReceiptRef,
    suspensionAuthorityReceiptDigest: asDigest(
      row.suspensionAuthorityReceiptDigest
    ),
    promotionEvidenceId: row.promotionEvidenceId,
    promotionEvidenceDigest: asDigest(row.promotionEvidenceDigest),
    profileId: row.profileId as SastProfileId,
    baselineManifestId: row.baselineManifestId,
    baselineManifestDigest: asDigest(row.baselineManifestDigest),
    baselineVerificationId: row.baselineVerificationId,
    baselineVerificationDigest: asDigest(row.baselineVerificationDigest),
    baselineBundleId: row.baselineBundleId,
    baselineBundleDigest: asDigest(row.baselineBundleDigest),
    baselineTransitionId: row.baselineTransitionId,
    baselineTransitionDigest: asDigest(row.baselineTransitionDigest),
    baselineSequence: row.baselineSequence,
    baselineTransitionedAt: row.baselineTransitionedAt.toISOString(),
    baselineState: row.baselineState as 'ACTIVE',
    incidentRef: row.incidentRef,
    actorRef: row.actorRef,
    actorRole: row.actorRole as SastRuleBundleRollbackActorRole,
    reasonRef: row.reasonRef,
    auditRef: row.auditRef,
    signatureRef: row.signatureRef,
    provenanceRef: row.provenanceRef,
    commandedAt: row.commandedAt.toISOString(),
    rollbackTargetDerived: row.rollbackTargetDerived as true,
    customerTargetAccepted: row.customerTargetAccepted as false,
    source: row.source as 'PLATFORM_RULE_GOVERNANCE',
    immutable: row.immutable as true,
    repositoryContentStored: row.repositoryContentStored as false,
    findingContentStored: row.findingContentStored as false,
    secretValueStored: row.secretValueStored as false,
    arbitraryPayloadStored: row.arbitraryPayloadStored as false
  };
}

function verificationFromRow(
  row: Readonly<VerificationRow>
): SastRuleBundleRollbackVerification {
  return {
    version: 'sast-rule-bundle-rollback-verification-v1',
    verificationId: row.id,
    verificationDigest: asDigest(row.verificationDigest),
    commandId: row.commandId,
    commandDigest: asDigest(row.commandDigest),
    signerIdentity: row.signerIdentity,
    signatureRef: row.signatureRef,
    provenanceRef: row.provenanceRef,
    verifiedAt: row.verifiedAt.toISOString(),
    signatureVerified: row.signatureVerified as true,
    provenanceVerified: row.provenanceVerified as true,
    trustedSigner: row.trustedSigner as true,
    signatureBytesStored: row.signatureBytesStored as false,
    provenancePayloadStored: row.provenancePayloadStored as false,
    repositoryContentStored: row.repositoryContentStored as false,
    secretValueStored: row.secretValueStored as false
  };
}

function approvalFromRow(
  row: Readonly<ApprovalRow>
): SastRuleBundleRollbackApproval {
  return {
    version: 'sast-rule-bundle-rollback-approval-v1',
    approvalId: row.id,
    approvalDigest: asDigest(row.approvalDigest),
    commandId: row.commandId,
    commandDigest: asDigest(row.commandDigest),
    role: row.role as SastRuleBundlePromotionApprovalRole,
    approverRef: row.approverRef,
    approvalRef: row.approvalRef,
    approvedAt: row.approvedAt.toISOString(),
    approved: row.approved as true,
    humanApproval: row.humanApproval as true,
    automatedApproval: row.automatedApproval as false,
    customerInputAccepted: row.customerInputAccepted as false
  };
}

function receiptFromRow(
  row: Readonly<ReceiptRow>,
  approvals: readonly Readonly<ReceiptApprovalRow>[]
): SastRuleBundleRollbackReceipt {
  return {
    version: 'sast-rule-bundle-rollback-receipt-v1',
    receiptRef: row.id,
    receiptDigest: asDigest(row.receiptDigest),
    commandId: row.commandId,
    commandDigest: asDigest(row.commandDigest),
    commandVerificationId: row.commandVerificationId,
    commandVerificationDigest: asDigest(row.commandVerificationDigest),
    candidateManifestId: row.candidateManifestId,
    candidateManifestDigest: asDigest(row.candidateManifestDigest),
    candidateBundleId: row.candidateBundleId,
    candidateBundleDigest: asDigest(row.candidateBundleDigest),
    suspendedTransitionId: row.suspendedTransitionId,
    suspendedTransitionDigest: asDigest(row.suspendedTransitionDigest),
    suspendedSequence: row.suspendedSequence,
    suspendedTransitionedAt: row.suspendedTransitionedAt.toISOString(),
    suspensionAuthorityReceiptRef: row.suspensionAuthorityReceiptRef,
    suspensionAuthorityReceiptDigest: asDigest(
      row.suspensionAuthorityReceiptDigest
    ),
    promotionEvidenceId: row.promotionEvidenceId,
    promotionEvidenceDigest: asDigest(row.promotionEvidenceDigest),
    profileId: row.profileId as SastProfileId,
    baselineManifestId: row.baselineManifestId,
    baselineManifestDigest: asDigest(row.baselineManifestDigest),
    baselineVerificationId: row.baselineVerificationId,
    baselineVerificationDigest: asDigest(row.baselineVerificationDigest),
    baselineBundleId: row.baselineBundleId,
    baselineBundleDigest: asDigest(row.baselineBundleDigest),
    baselineTransitionId: row.baselineTransitionId,
    baselineTransitionDigest: asDigest(row.baselineTransitionDigest),
    baselineSequence: row.baselineSequence,
    baselineTransitionedAt: row.baselineTransitionedAt.toISOString(),
    baselineState: row.baselineState as 'ACTIVE',
    approvalCount: row.approvalCount as 2,
    approvals: approvals.map(approvalBindingFromRow),
    approvalSetDigest: asDigest(row.approvalSetDigest),
    actorRef: row.actorRef,
    reasonRef: row.reasonRef,
    auditRef: row.auditRef,
    commandedAt: row.commandedAt.toISOString(),
    requestedAt: row.requestedAt.toISOString(),
    issuedAt: row.issuedAt.toISOString(),
    fromState: row.fromState as 'SUSPENDED',
    toState: row.toState as 'ROLLED_BACK',
    rollbackTargetDerived: row.rollbackTargetDerived as true,
    baselineMutationAuthorized: row.baselineMutationAuthorized as false,
    historicalMutationAuthorized: row.historicalMutationAuthorized as false,
    scannerSetMutationAuthorized: row.scannerSetMutationAuthorized as false,
    findingAuthority: row.findingAuthority as false,
    policyAuthority: row.policyAuthority as false,
    publicationAuthority: row.publicationAuthority as false,
    scmWriteAuthority: row.scmWriteAuthority as false,
    customerInputAccepted: row.customerInputAccepted as false,
    repositoryContentStored: row.repositoryContentStored as false,
    findingContentStored: row.findingContentStored as false,
    secretValueStored: row.secretValueStored as false,
    arbitraryPayloadStored: row.arbitraryPayloadStored as false
  };
}

function approvalBindingFromRow(
  row: Readonly<ReceiptApprovalRow>
): SastRuleBundleRollbackApprovalBinding {
  return {
    approvalId: row.approvalId,
    approvalDigest: asDigest(row.approvalDigest),
    role: row.role as SastRuleBundlePromotionApprovalRole,
    approverRef: row.approverRef,
    approvedAt: row.approvedAt.toISOString()
  };
}

function verificationMatchesCommand(
  verification: Readonly<SastRuleBundleRollbackVerification>,
  command: Readonly<SastRuleBundleRollbackCommand>
): boolean {
  return (
    verification.commandId === command.commandId &&
    verification.commandDigest === command.commandDigest &&
    verification.signatureRef === command.signatureRef &&
    verification.provenanceRef === command.provenanceRef &&
    Date.parse(verification.verifiedAt) >= Date.parse(command.commandedAt)
  );
}

function assertCommandValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleRollbackCommand {
  if (
    !isSastRuleBundleRollbackCommandValid(
      value,
      digestSastRuleBundleCanonical
    )
  ) {
    throw persistenceError(reason);
  }
}

function assertVerificationValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleRollbackVerification {
  if (
    !isSastRuleBundleRollbackVerificationValid(
      value,
      digestSastRuleBundleCanonical
    )
  ) {
    throw persistenceError(reason);
  }
}

function assertApprovalValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleRollbackApproval {
  if (
    !isSastRuleBundleRollbackApprovalValid(
      value,
      digestSastRuleBundleCanonical
    )
  ) {
    throw persistenceError(reason);
  }
}

function assertReceiptValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleRollbackReceipt {
  if (
    !isSastRuleBundleRollbackReceiptValid(
      value,
      digestSastRuleBundleCanonical
    )
  ) {
    throw persistenceError(reason);
  }
}

function asDigest(value: string): `sha256:${string}` {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) {
    throw persistenceError('LEDGER_CORRUPT');
  }
  return value as `sha256:${string}`;
}

function roleOrder(role: SastRuleBundlePromotionApprovalRole): number {
  switch (role) {
    case 'SECURITY_ENGINEERING':
      return 0;
    case 'SCAN_PLATFORM':
      return 1;
    case 'SECURITY_OPERATIONS':
      return 2;
  }
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function persistenceError(
  reason: SastRuleBundleRollbackPersistenceError['reason']
): SastRuleBundleRollbackPersistenceError {
  return new SastRuleBundleRollbackPersistenceError(reason);
}

function toPersistenceError(error: unknown): Error {
  if (error instanceof SastRuleBundleRollbackPersistenceError) return error;
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2002' || error.code === 'P2034') {
      return persistenceError('REPLAY_CONFLICT');
    }
    if (error.code === 'P2003' || error.code === 'P2004') {
      return persistenceError('STATE_STALE');
    }
  }
  return error instanceof Error
    ? error
    : new Error('Unknown SAST rule-bundle rollback persistence failure.');
}

function isUniqueConflict(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002'
  );
}
