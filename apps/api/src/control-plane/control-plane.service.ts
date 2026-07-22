import { BadRequestException, ConflictException, Injectable, NotFoundException } from "@nestjs/common";
import { randomUUID } from 'node:crypto';
import {
  buildCanonicalScanKey,
  buildCommentDispatchIdempotencyKey,
  COMMENT_DISPATCH_AUDIT_EVENT_MAX_PAGE_SIZE,
  COMMENT_DISPATCH_MAX_CLAIM_LEASE_SECONDS,
  COMMENT_DISPATCH_OUTBOX_MAX_PAGE_SIZE,
  shouldEscalateIsolation,
  type CommentDispatchAuditEvent,
  type CommentDispatchAuditEventListQuery,
  type CommentDispatchEnqueueRequest,
  type CommentDispatchOutboxClaimRequest,
  type CommentDispatchOutboxItem,
  type CommentDispatchOutboxListQuery,
  type CommentDispatchOutboxLeaseRenewalRequest,
  type CommentDispatchOutboxStatusUpdateRequest,
  type CommentDispatchPlan,
  type CommentDispatchPlanRequest,
  type IsolationClass,
  type SastUserVisiblePlanningState
} from '@aegisai/shared';

import type {
  ControlPlaneIntegration,
  ControlPlaneRepositoryBinding,
  ControlPlaneScanRequest,
  CreateScanRequestInput,
  GithubInstallationWebhookAck,
  GithubInstallationWebhookInput,
  GithubWebhookRepositoryInput,
  InstallIntegrationInput,
  InstallIntegrationOptions,
  InstallRepositoryInput
} from "./control-plane.types";
import { GithubAppInstallationClient } from "./github-app-installation.client";
import { GithubAppInstallationStateService } from "./github-app-installation-state.service";
import { GitlabCloudIntegrationClient } from "./gitlab-cloud-integration.client";
import { ControlPlaneScanRequestStore } from './control-plane-scan-request.store';

@Injectable()
export class ControlPlaneService {
  private readonly integrations = new Map<string, ControlPlaneIntegration>();
  private readonly repositoryBindings = new Map<string, ControlPlaneRepositoryBinding>();
  private readonly commentDispatchPlans = new Map<string, CommentDispatchPlan>();
  private readonly commentDispatchOutboxItems = new Map<string, CommentDispatchOutboxItem>();
  private readonly commentDispatchAuditEvents: CommentDispatchAuditEvent[] = [];

  private commentDispatchSequence = 0;
  private commentDispatchOutboxSequence = 0;
  private commentDispatchAuditSequence = 0;

  constructor(
    private readonly githubAppInstallationClient: GithubAppInstallationClient,
    private readonly githubAppInstallationState: GithubAppInstallationStateService,
    private readonly gitlabCloudIntegrationClient: GitlabCloudIntegrationClient,
    private readonly scanRequestStore: ControlPlaneScanRequestStore
  ) {}

  async installGithubAppIntegration(input: InstallIntegrationInput): Promise<ControlPlaneIntegration> {
    const repositories =
      input.repositories ??
      (await this.githubAppInstallationClient.listInstallationRepositories(input.externalInstallationId));

    const integration = this.installIntegration(
      {
        ...input,
        repositories
      },
      {
        provider: "GITHUB",
        integrationType: "GITHUB_APP"
      }
    );

    await this.githubAppInstallationState.persistInstallation(
      integration,
      this.listRepositoryBindings(integration.tenantId).filter(
        (binding) => binding.scmIntegrationId === integration.id
      )
    );

    return integration;
  }

  async installGitlabCloudIntegration(input: InstallIntegrationInput): Promise<ControlPlaneIntegration> {
    const repositories =
      input.repositories ??
      (await this.gitlabCloudIntegrationClient.listIntegrationRepositories(
        input.externalInstallationId,
        input.runtimeAccessToken
      ));

    return this.installIntegration(
      {
        ...input,
        repositories,
        runtimeAccessToken: undefined
      },
      {
        provider: "GITLAB",
        integrationType: "GITLAB_CLOUD_INTEGRATION"
      }
    );
  }

  installIntegration(
    input: InstallIntegrationInput,
    options: InstallIntegrationOptions
  ): ControlPlaneIntegration {
    const existingIntegration = Array.from(this.integrations.values()).find(
      (candidate) =>
        candidate.tenantId === input.tenantId &&
        candidate.provider === options.provider &&
        candidate.externalInstallationId === input.externalInstallationId
    );
    if (existingIntegration) {
      return existingIntegration;
    }

    const integration: ControlPlaneIntegration = {
      id: `integration_${randomUUID()}`,
      tenantId: input.tenantId,
      provider: options.provider,
      integrationType: options.integrationType,
      externalInstallationId: input.externalInstallationId,
      repoReadPrincipalId: input.repoReadPrincipalId,
      commentWritePrincipalId: input.commentWritePrincipalId,
      integrationAdminPrincipalId: input.integrationAdminPrincipalId,
      status: "ACTIVE"
    };

    this.integrations.set(integration.id, integration);

    for (const repository of input.repositories ?? []) {
      const binding: ControlPlaneRepositoryBinding = {
        id: `repository_binding_${randomUUID()}`,
        tenantId: input.tenantId,
        scmIntegrationId: integration.id,
        providerRepoId: repository.providerRepoId,
        fullName: repository.fullName,
        defaultBranch: repository.defaultBranch,
        isPrivate: repository.isPrivate
      };
      this.repositoryBindings.set(binding.id, binding);
    }

    return integration;
  }

  listIntegrations(tenantId: string): ControlPlaneIntegration[] {
    return Array.from(this.integrations.values()).filter((integration) => integration.tenantId === tenantId);
  }

  removeIntegration(tenantId: string, integrationId: string): { deleted: true; id: string } {
    const integration = this.integrations.get(integrationId);
    if (!integration || integration.tenantId !== tenantId) {
      throw new NotFoundException("Integration not found");
    }

    this.integrations.delete(integrationId);

    for (const binding of this.repositoryBindings.values()) {
      if (binding.scmIntegrationId === integrationId) {
        this.repositoryBindings.delete(binding.id);
      }
    }

    return { deleted: true, id: integrationId };
  }

  listRepositoryBindings(tenantId: string): ControlPlaneRepositoryBinding[] {
    return Array.from(this.repositoryBindings.values()).filter((binding) => binding.tenantId === tenantId);
  }

  async reconcileGithubInstallationWebhook(
    event: string,
    input: GithubInstallationWebhookInput
  ): Promise<GithubInstallationWebhookAck> {
    const externalInstallationId = String(input.installation?.id ?? "");
    if (!externalInstallationId) {
      throw new BadRequestException("GitHub installation webhook is missing installation id");
    }

    const integration = this.findGithubAppIntegration(externalInstallationId);

    const addedRepositories = this.normalizeGithubRepositories(
      input.repositories_added ?? (input.action === "created" ? input.repositories : undefined)
    );
    const removedProviderRepoIds = this.normalizeGithubRepositories(input.repositories_removed).map(
      (repository) => repository.providerRepoId
    );

    const addedBindings = addedRepositories.map((repository) =>
      this.upsertRepositoryBinding(integration, repository)
    );

    for (const providerRepoId of removedProviderRepoIds) {
      this.removeRepositoryBinding(integration, providerRepoId);
    }

    await this.githubAppInstallationState.reconcileRepositories(
      integration,
      addedBindings,
      removedProviderRepoIds,
      event,
      input.action
    );

    return {
      acknowledged: true,
      provider: "GITHUB",
      event,
      externalInstallationId,
      addedRepositoryCount: addedRepositories.length,
      removedRepositoryCount: removedProviderRepoIds.length
    };
  }

  async createScanRequest(input: CreateScanRequestInput): Promise<ControlPlaneScanRequest> {
    const repositoryBinding = this.repositoryBindings.get(input.repositoryBindingId);
    if (!repositoryBinding || repositoryBinding.tenantId !== input.tenantId) {
      throw new NotFoundException("Repository binding not found for tenant");
    }
    const integration = this.integrations.get(repositoryBinding.scmIntegrationId);
    if (!integration || integration.tenantId !== input.tenantId) {
      throw new NotFoundException('SCM integration not found for tenant');
    }

    const isolationClass: IsolationClass =
      input.isolationSignals && shouldEscalateIsolation(input.isolationSignals)
        ? "RESTRICTED"
        : "STANDARD";

    const canonicalKey = buildCanonicalScanKey(input);
    const scanRequest: ControlPlaneScanRequest = {
      id: `scan_request_${randomUUID()}`,
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      lane: input.lane,
      targetRef: input.targetRef,
      commitSha: input.commitSha,
      policyVersion: input.policyVersion,
      scannerSetVersion: input.scannerSetVersion,
      canonicalKey,
      isolationClass,
      status: "QUEUED"
    };

    return this.scanRequestStore.createOrGet({
      scanRequest,
      repositoryBinding,
      integration
    });
  }

  async getScanRequest(
    tenantId: string,
    scanRequestId: string
  ): Promise<ControlPlaneScanRequest> {
    const scanRequest = await this.scanRequestStore.find(tenantId, scanRequestId);
    if (!scanRequest) {
      throw new NotFoundException("Scan request not found");
    }

    return scanRequest;
  }

  async recordSastPlanningState(
    tenantId: string,
    scanRequestId: string,
    planning: SastUserVisiblePlanningState
  ): Promise<ControlPlaneScanRequest> {
    return this.scanRequestStore.recordPlanningState({
      tenantId,
      scanRequestId,
      planning
    });
  }

  async assertSastQueueReservationAllowed(
    tenantId: string,
    scanRequestId: string,
    canonicalScanKey?: `sha256:${string}`
  ): Promise<void> {
    const scanRequest = await this.getScanRequest(tenantId, scanRequestId);

    if (scanRequest.status !== 'QUEUED' && scanRequest.status !== 'PLANNING') {
      throw new ConflictException('SAST planning cannot rewrite a terminal or running scan.');
    }

    const existingPlanning = scanRequest.sastPlanning;
    if (
      canonicalScanKey !== undefined &&
      existingPlanning?.canonicalScanKey &&
      canonicalScanKey !== existingPlanning.canonicalScanKey
    ) {
      throw new ConflictException('SAST canonical planning identity is immutable.');
    }
  }

  async updateScanRequestStatus(
    tenantId: string,
    scanRequestId: string,
    status: ControlPlaneScanRequest['status']
  ): Promise<ControlPlaneScanRequest> {
    return this.scanRequestStore.updateStatus({ tenantId, scanRequestId, status });
  }

  planCommentDispatch(input: CommentDispatchPlanRequest): CommentDispatchPlan {
    this.assertSafeCommentDispatchPayload(input);

    const repositoryBinding = this.repositoryBindings.get(input.repositoryBindingId);
    if (!repositoryBinding || repositoryBinding.tenantId !== input.tenantId) {
      throw new NotFoundException("Repository binding not found for tenant");
    }

    const integration = this.integrations.get(repositoryBinding.scmIntegrationId);
    if (!integration || integration.tenantId !== input.tenantId) {
      throw new NotFoundException("SCM integration not found for tenant");
    }

    if (!integration.commentWritePrincipalId) {
      throw new BadRequestException("Repository binding does not have a comment-write principal.");
    }

    if (!input.policyDecision.commentAllowed) {
      throw new BadRequestException("Policy decision does not allow comment dispatch.");
    }

    if (
      input.policyDecision.tenantId !== input.tenantId ||
      input.finding.tenantId !== input.tenantId ||
      input.policyDecision.findingId !== input.finding.id
    ) {
      throw new BadRequestException("Comment dispatch input is not tenant or finding aligned.");
    }

    const idempotencyKey = buildCommentDispatchIdempotencyKey(input);
    const existingPlan = this.commentDispatchPlans.get(idempotencyKey);
    if (existingPlan) {
      return existingPlan;
    }

    const plan: CommentDispatchPlan = {
      id: `comment_dispatch_plan_${++this.commentDispatchSequence}`,
      idempotencyKey,
      tenantId: input.tenantId,
      repositoryBindingId: repositoryBinding.id,
      provider: integration.provider,
      providerRepoId: repositoryBinding.providerRepoId,
      commentWritePrincipalId: integration.commentWritePrincipalId,
      policyDecisionId: input.policyDecision.id,
      findingId: input.finding.id,
      targetRef: input.targetRef,
      commitSha: input.commitSha,
      dispatchAllowed: true
    };

    this.commentDispatchAuditEvents.push({
      id: `audit_event_${++this.commentDispatchAuditSequence}`,
      tenantId: input.tenantId,
      eventType: "comment_dispatch.planned",
      actor: "comment-dispatcher",
      targetType: "comment_dispatch_plan",
      targetId: plan.id,
      occurredAt: new Date(0).toISOString(),
      metadata: {
        idempotencyKey,
        repositoryBindingId: repositoryBinding.id,
        provider: integration.provider,
        providerRepoId: repositoryBinding.providerRepoId,
        policyDecisionId: input.policyDecision.id,
        findingId: input.finding.id,
        targetRef: input.targetRef,
        commitSha: input.commitSha,
        commentWritePrincipalId: integration.commentWritePrincipalId
      }
    });

    this.commentDispatchPlans.set(idempotencyKey, plan);

    return plan;
  }

  listCommentDispatchAuditEvents(query: CommentDispatchAuditEventListQuery): CommentDispatchAuditEvent[] {
    this.assertSafeCommentDispatchPayload(query);

    if (!query.tenantId) {
      throw new BadRequestException("Comment dispatch audit event reads require a tenant id.");
    }

    if (query.eventType !== undefined && !this.isCommentDispatchAuditEventType(query.eventType)) {
      throw new BadRequestException("Comment dispatch audit event type filter is invalid.");
    }

    if (
      query.targetType !== undefined &&
      query.targetType !== "comment_dispatch_plan" &&
      query.targetType !== "comment_dispatch_outbox_item"
    ) {
      throw new BadRequestException("Comment dispatch audit target type filter is invalid.");
    }

    if (query.order !== undefined && query.order !== "ASC" && query.order !== "DESC") {
      throw new BadRequestException("Comment dispatch audit event order filter is invalid.");
    }

    if (query.provider !== undefined && query.provider !== "GITHUB" && query.provider !== "GITLAB") {
      throw new BadRequestException("Comment dispatch audit provider filter is invalid.");
    }

    const limit = this.parseCommentDispatchAuditEventLimit(query.limit);
    const order = query.order ?? "ASC";

    const events = this.commentDispatchAuditEvents.filter(
      (event) =>
        event.tenantId === query.tenantId &&
        (query.repositoryBindingId === undefined ||
          event.metadata.repositoryBindingId === query.repositoryBindingId) &&
        (query.provider === undefined || event.metadata.provider === query.provider) &&
        (query.providerRepoId === undefined || event.metadata.providerRepoId === query.providerRepoId) &&
        (query.idempotencyKey === undefined || event.metadata.idempotencyKey === query.idempotencyKey) &&
        (query.eventType === undefined || event.eventType === query.eventType) &&
        (query.targetType === undefined || event.targetType === query.targetType) &&
        (query.targetId === undefined || event.targetId === query.targetId)
    );
    const orderedEvents = order === "ASC" ? events : [...events].reverse();

    return limit === undefined ? orderedEvents : orderedEvents.slice(0, limit);
  }

  enqueueCommentDispatch(input: CommentDispatchEnqueueRequest): CommentDispatchOutboxItem {
    this.assertSafeCommentDispatchPayload(input);

    const plan = Array.from(this.commentDispatchPlans.values()).find(
      (candidate) => candidate.id === input.planId && candidate.tenantId === input.tenantId
    );
    if (!plan) {
      throw new NotFoundException("Comment dispatch plan not found for tenant");
    }

    const existingOutboxItem = this.commentDispatchOutboxItems.get(plan.id);
    if (existingOutboxItem) {
      return existingOutboxItem;
    }

    const outboxItem: CommentDispatchOutboxItem = {
      id: `comment_dispatch_outbox_${++this.commentDispatchOutboxSequence}`,
      tenantId: plan.tenantId,
      planId: plan.id,
      idempotencyKey: plan.idempotencyKey,
      repositoryBindingId: plan.repositoryBindingId,
      provider: plan.provider,
      providerRepoId: plan.providerRepoId,
      commentWritePrincipalId: plan.commentWritePrincipalId,
      policyDecisionId: plan.policyDecisionId,
      findingId: plan.findingId,
      targetRef: plan.targetRef,
      commitSha: plan.commitSha,
      status: "PENDING",
      enqueuedAt: new Date(0).toISOString()
    };

    this.commentDispatchOutboxItems.set(plan.id, outboxItem);
    this.commentDispatchAuditEvents.push({
      id: `audit_event_${++this.commentDispatchAuditSequence}`,
      tenantId: plan.tenantId,
      eventType: "comment_dispatch.enqueued",
      actor: "comment-dispatcher",
      targetType: "comment_dispatch_outbox_item",
      targetId: outboxItem.id,
      occurredAt: new Date(0).toISOString(),
      metadata: {
        outboxItemId: outboxItem.id,
        planId: plan.id,
        idempotencyKey: plan.idempotencyKey,
        repositoryBindingId: plan.repositoryBindingId,
        provider: plan.provider,
        providerRepoId: plan.providerRepoId,
        policyDecisionId: plan.policyDecisionId,
        findingId: plan.findingId,
        targetRef: plan.targetRef,
        commitSha: plan.commitSha,
        commentWritePrincipalId: plan.commentWritePrincipalId
      }
    });

    return outboxItem;
  }

  listCommentDispatchOutbox(query: CommentDispatchOutboxListQuery): CommentDispatchOutboxItem[] {
    this.assertSafeCommentDispatchPayload(query);

    if (!query.tenantId) {
      throw new BadRequestException("Comment dispatch outbox reads require a tenant id.");
    }

    if (
      query.status !== undefined &&
      query.status !== "PENDING" &&
      query.status !== "PUBLISHED" &&
      query.status !== "FAILED" &&
      query.status !== "CANCELED"
    ) {
      throw new BadRequestException("Comment dispatch outbox status filter is invalid.");
    }

    if (query.order !== undefined && query.order !== "ASC" && query.order !== "DESC") {
      throw new BadRequestException("Comment dispatch outbox order filter is invalid.");
    }

    if (query.provider !== undefined && query.provider !== "GITHUB" && query.provider !== "GITLAB") {
      throw new BadRequestException("Comment dispatch outbox provider filter is invalid.");
    }

    const limit = this.parseCommentDispatchOutboxLimit(query.limit);
    const order = query.order ?? "ASC";

    const items = Array.from(this.commentDispatchOutboxItems.values()).filter(
      (item) =>
        item.tenantId === query.tenantId &&
        (query.repositoryBindingId === undefined || item.repositoryBindingId === query.repositoryBindingId) &&
        (query.provider === undefined || item.provider === query.provider) &&
        (query.providerRepoId === undefined || item.providerRepoId === query.providerRepoId) &&
        (query.idempotencyKey === undefined || item.idempotencyKey === query.idempotencyKey) &&
        (query.status === undefined || item.status === query.status) &&
        (query.workerId === undefined || item.claimedBy === query.workerId)
    );
    const orderedItems = order === "ASC" ? items : [...items].reverse();

    return limit === undefined ? orderedItems : orderedItems.slice(0, limit);
  }

  claimCommentDispatchOutbox(input: CommentDispatchOutboxClaimRequest): CommentDispatchOutboxItem | null {
    this.assertSafeCommentDispatchPayload(input);

    this.assertValidCommentDispatchLease(input.workerId, input.leaseSeconds);

    const claimedAt = new Date(0).toISOString();
    const leaseExpiresAt = new Date(input.leaseSeconds * 1000).toISOString();
    const existingWorkerClaim = Array.from(this.commentDispatchOutboxItems.values()).find(
      (item) =>
        item.tenantId === input.tenantId &&
        item.status === "PENDING" &&
        item.claimedBy === input.workerId &&
        item.leaseExpiresAt !== undefined &&
        item.leaseExpiresAt > claimedAt
    );
    if (existingWorkerClaim) {
      return existingWorkerClaim;
    }

    const claimableOutboxItem = Array.from(this.commentDispatchOutboxItems.values()).find(
      (item) =>
        item.tenantId === input.tenantId &&
        item.status === "PENDING" &&
        (item.leaseExpiresAt === undefined || item.leaseExpiresAt <= claimedAt)
    );
    if (!claimableOutboxItem) {
      return null;
    }

    const claimedOutboxItem: CommentDispatchOutboxItem = {
      ...claimableOutboxItem,
      claimedBy: input.workerId,
      claimedAt,
      leaseExpiresAt
    };

    this.commentDispatchOutboxItems.set(claimedOutboxItem.planId, claimedOutboxItem);
    this.commentDispatchAuditEvents.push({
      id: `audit_event_${++this.commentDispatchAuditSequence}`,
      tenantId: input.tenantId,
      eventType: "comment_dispatch.outbox_claimed",
      actor: "comment-dispatcher",
      targetType: "comment_dispatch_outbox_item",
      targetId: claimedOutboxItem.id,
      occurredAt: claimedAt,
      metadata: {
        outboxItemId: claimedOutboxItem.id,
        planId: claimedOutboxItem.planId,
        workerId: input.workerId,
        claimedAt,
        leaseExpiresAt,
        repositoryBindingId: claimedOutboxItem.repositoryBindingId,
        provider: claimedOutboxItem.provider,
        findingId: claimedOutboxItem.findingId,
        commitSha: claimedOutboxItem.commitSha
      }
    });

    return claimedOutboxItem;
  }

  renewCommentDispatchOutboxLease(
    outboxItemId: string,
    input: CommentDispatchOutboxLeaseRenewalRequest
  ): CommentDispatchOutboxItem {
    this.assertSafeCommentDispatchPayload(input);
    this.assertValidCommentDispatchLease(input.workerId, input.leaseSeconds);

    const renewedAt = new Date(0).toISOString();
    const outboxEntry = Array.from(this.commentDispatchOutboxItems.entries()).find(
      ([, item]) => item.id === outboxItemId && item.tenantId === input.tenantId
    );
    if (!outboxEntry) {
      throw new NotFoundException("Comment dispatch outbox item not found for tenant");
    }

    const [planId, outboxItem] = outboxEntry;
    if (
      outboxItem.status !== "PENDING" ||
      outboxItem.claimedBy !== input.workerId ||
      outboxItem.claimedAt === undefined ||
      outboxItem.leaseExpiresAt === undefined ||
      outboxItem.leaseExpiresAt <= renewedAt
    ) {
      throw new BadRequestException("Comment dispatch outbox lease renewal requires an active worker claim.");
    }

    const leaseExpiresAt = new Date(input.leaseSeconds * 1000).toISOString();
    const renewedOutboxItem: CommentDispatchOutboxItem = {
      ...outboxItem,
      leaseExpiresAt
    };

    this.commentDispatchOutboxItems.set(planId, renewedOutboxItem);
    this.commentDispatchAuditEvents.push({
      id: `audit_event_${++this.commentDispatchAuditSequence}`,
      tenantId: input.tenantId,
      eventType: "comment_dispatch.outbox_lease_renewed",
      actor: "comment-dispatcher",
      targetType: "comment_dispatch_outbox_item",
      targetId: outboxItem.id,
      occurredAt: renewedAt,
      metadata: {
        outboxItemId: outboxItem.id,
        planId: outboxItem.planId,
        workerId: input.workerId,
        claimedAt: outboxItem.claimedAt,
        leaseExpiresAt,
        repositoryBindingId: outboxItem.repositoryBindingId,
        provider: outboxItem.provider,
        findingId: outboxItem.findingId,
        commitSha: outboxItem.commitSha
      }
    });

    return renewedOutboxItem;
  }

  updateCommentDispatchOutboxStatus(
    outboxItemId: string,
    input: CommentDispatchOutboxStatusUpdateRequest
  ): CommentDispatchOutboxItem {
    this.assertSafeCommentDispatchPayload(input);

    if (input.status !== "FAILED" && input.status !== "CANCELED") {
      throw new BadRequestException("Only FAILED or CANCELED outbox status updates are accepted in this milestone.");
    }

    if (!input.workerId) {
      throw new BadRequestException("Comment dispatch outbox status updates require the claiming worker id.");
    }

    const outboxEntry = Array.from(this.commentDispatchOutboxItems.entries()).find(
      ([, item]) => item.id === outboxItemId && item.tenantId === input.tenantId
    );
    if (!outboxEntry) {
      throw new NotFoundException("Comment dispatch outbox item not found for tenant");
    }

    const [planId, outboxItem] = outboxEntry;
    const statusUpdatedAt = new Date(0).toISOString();
    if (
      outboxItem.claimedBy !== input.workerId ||
      outboxItem.leaseExpiresAt === undefined ||
      outboxItem.leaseExpiresAt <= statusUpdatedAt
    ) {
      throw new BadRequestException("Comment dispatch outbox status updates require an active worker claim.");
    }

    if (outboxItem.status === input.status && outboxItem.statusReason === input.statusReason) {
      return outboxItem;
    }

    if (outboxItem.status === "FAILED" || outboxItem.status === "CANCELED") {
      throw new BadRequestException("Terminal comment dispatch outbox statuses cannot be rewritten.");
    }

    const updatedOutboxItem: CommentDispatchOutboxItem = {
      ...outboxItem,
      status: input.status,
      statusReason: input.statusReason,
      statusUpdatedAt
    };

    this.commentDispatchOutboxItems.set(planId, updatedOutboxItem);
    this.commentDispatchAuditEvents.push({
      id: `audit_event_${++this.commentDispatchAuditSequence}`,
      tenantId: input.tenantId,
      eventType: "comment_dispatch.outbox_status_updated",
      actor: "comment-dispatcher",
      targetType: "comment_dispatch_outbox_item",
      targetId: outboxItem.id,
      occurredAt: statusUpdatedAt,
      metadata: {
        outboxItemId: outboxItem.id,
        planId: outboxItem.planId,
        previousStatus: outboxItem.status,
        nextStatus: updatedOutboxItem.status,
        statusReason: updatedOutboxItem.statusReason,
        statusUpdatedAt: updatedOutboxItem.statusUpdatedAt,
        workerId: input.workerId,
        repositoryBindingId: outboxItem.repositoryBindingId,
        provider: outboxItem.provider,
        findingId: outboxItem.findingId,
        commitSha: outboxItem.commitSha
      }
    });

    return updatedOutboxItem;
  }

  private findGithubAppIntegration(
    externalInstallationId: string
  ): ControlPlaneIntegration {
    const integration = Array.from(this.integrations.values()).find(
      (candidate) =>
        candidate.provider === "GITHUB" &&
        candidate.integrationType === "GITHUB_APP" &&
        candidate.externalInstallationId === externalInstallationId
    );

    if (!integration) {
      throw new NotFoundException("GitHub App installation integration not found");
    }

    return integration;
  }

  private upsertRepositoryBinding(
    integration: ControlPlaneIntegration,
    repository: InstallRepositoryInput
  ): ControlPlaneRepositoryBinding {
    const existing = Array.from(this.repositoryBindings.values()).find(
      (binding) =>
        binding.tenantId === integration.tenantId &&
        binding.scmIntegrationId === integration.id &&
        binding.providerRepoId === repository.providerRepoId
    );

    const binding: ControlPlaneRepositoryBinding = {
      id: existing?.id ?? `repository_binding_${randomUUID()}`,
      tenantId: integration.tenantId,
      scmIntegrationId: integration.id,
      providerRepoId: repository.providerRepoId,
      fullName: repository.fullName,
      defaultBranch: repository.defaultBranch,
      isPrivate: repository.isPrivate
    };

    this.repositoryBindings.set(binding.id, binding);

    return binding;
  }

  private removeRepositoryBinding(
    integration: ControlPlaneIntegration,
    providerRepoId: string
  ): void {
    for (const binding of this.repositoryBindings.values()) {
      if (
        binding.tenantId === integration.tenantId &&
        binding.scmIntegrationId === integration.id &&
        binding.providerRepoId === providerRepoId
      ) {
        this.repositoryBindings.delete(binding.id);
      }
    }
  }

  private normalizeGithubRepositories(
    repositories: GithubWebhookRepositoryInput[] | undefined
  ): InstallRepositoryInput[] {
    return (repositories ?? []).map((repository) => {
      const providerRepoId = String(repository.providerRepoId ?? repository.id ?? "");
      const fullName = repository.fullName ?? repository.full_name ?? "";
      if (!providerRepoId || !fullName) {
        throw new BadRequestException("GitHub repository webhook entry is missing repository id or full name");
      }

      return {
        providerRepoId,
        fullName,
        defaultBranch: repository.defaultBranch ?? repository.default_branch ?? "main",
        isPrivate: repository.isPrivate ?? repository.private ?? true
      };
    });
  }

  private assertSafeCommentDispatchPayload(input: unknown): void {
    const serialized = JSON.stringify(input);
    const forbiddenKeys = [
      "accessToken",
      "refreshToken",
      "tokenValue",
      "secretValue",
      "sourceArchive",
      "fullRepository",
      "rawScannerPayload",
      "repoReadPrincipalId",
      "integrationAdminPrincipalId",
      "externalCommentId",
      "policyOverride",
      "findingOverride"
    ];

    for (const forbiddenKey of forbiddenKeys) {
      if (new RegExp(forbiddenKey, "i").test(serialized)) {
        throw new BadRequestException("Comment dispatch payload contains forbidden sensitive or authority content.");
      }
    }
  }

  private isCommentDispatchAuditEventType(eventType: string): eventType is CommentDispatchAuditEvent["eventType"] {
    return (
      eventType === "comment_dispatch.planned" ||
      eventType === "comment_dispatch.enqueued" ||
      eventType === "comment_dispatch.outbox_claimed" ||
      eventType === "comment_dispatch.outbox_lease_renewed" ||
      eventType === "comment_dispatch.outbox_status_updated"
    );
  }

  private parseCommentDispatchAuditEventLimit(limit: number | string | undefined): number | undefined {
    if (limit === undefined) {
      return undefined;
    }

    const parsedLimit = typeof limit === "number" ? limit : Number(limit);
    if (
      !Number.isInteger(parsedLimit) ||
      parsedLimit <= 0 ||
      parsedLimit > COMMENT_DISPATCH_AUDIT_EVENT_MAX_PAGE_SIZE
    ) {
      throw new BadRequestException("Comment dispatch audit event limit must be an integer from 1 through 100.");
    }

    return parsedLimit;
  }

  private parseCommentDispatchOutboxLimit(limit: number | string | undefined): number | undefined {
    if (limit === undefined) {
      return undefined;
    }

    const parsedLimit = typeof limit === "number" ? limit : Number(limit);
    if (!Number.isInteger(parsedLimit) || parsedLimit <= 0 || parsedLimit > COMMENT_DISPATCH_OUTBOX_MAX_PAGE_SIZE) {
      throw new BadRequestException("Comment dispatch outbox limit must be an integer from 1 through 100.");
    }

    return parsedLimit;
  }

  private assertValidCommentDispatchLease(workerId: string, leaseSeconds: number): void {
    if (
      !workerId ||
      !Number.isInteger(leaseSeconds) ||
      leaseSeconds <= 0 ||
      leaseSeconds > COMMENT_DISPATCH_MAX_CLAIM_LEASE_SECONDS
    ) {
      throw new BadRequestException("Comment dispatch outbox lease requires a worker id and 1-900 lease seconds.");
    }
  }
}
