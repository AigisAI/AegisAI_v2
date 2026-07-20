import { Body, Controller, Get, Param, Patch, Post, Query, UseGuards } from '@nestjs/common';

import type {
  CommentDispatchAuditEventListQuery,
  CommentDispatchEnqueueRequest,
  CommentDispatchOutboxClaimRequest,
  CommentDispatchOutboxListQuery,
  CommentDispatchOutboxLeaseRenewalRequest,
  CommentDispatchOutboxStatusUpdateRequest,
  CommentDispatchPlanRequest
} from '@aegisai/shared';
import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../common/security/internal-service.guard';
import { ControlPlaneService } from "./control-plane.service";

@Controller("comment-dispatches")
export class CommentDispatchesController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post("plan")
  @UseGuards(InternalServiceGuard)
  plan(@Body() body: CommentDispatchPlanRequest) {
    return this.controlPlaneService.planCommentDispatch(body);
  }

  @Post("enqueue")
  @UseGuards(InternalServiceGuard)
  enqueue(@Body() body: CommentDispatchEnqueueRequest) {
    return this.controlPlaneService.enqueueCommentDispatch(body);
  }

  @Get("audit-events")
  @UseGuards(SessionAuthGuard)
  listAuditEvents(
    @CurrentTenant() tenantId: string,
    @Query() query: CommentDispatchAuditEventListQuery
  ) {
    return this.controlPlaneService.listCommentDispatchAuditEvents({ ...query, tenantId });
  }

  @Get("outbox")
  @UseGuards(SessionAuthGuard)
  listOutbox(@CurrentTenant() tenantId: string, @Query() query: CommentDispatchOutboxListQuery) {
    return this.controlPlaneService.listCommentDispatchOutbox({ ...query, tenantId });
  }

  @Post("outbox/claim")
  @UseGuards(InternalServiceGuard)
  claimOutbox(@Body() body: CommentDispatchOutboxClaimRequest) {
    return this.controlPlaneService.claimCommentDispatchOutbox(body);
  }

  @Patch("outbox/:outboxItemId/lease")
  @UseGuards(InternalServiceGuard)
  renewOutboxLease(
    @Param("outboxItemId") outboxItemId: string,
    @Body() body: CommentDispatchOutboxLeaseRenewalRequest
  ) {
    return this.controlPlaneService.renewCommentDispatchOutboxLease(outboxItemId, body);
  }

  @Patch("outbox/:outboxItemId/status")
  @UseGuards(InternalServiceGuard)
  updateOutboxStatus(
    @Param("outboxItemId") outboxItemId: string,
    @Body() body: CommentDispatchOutboxStatusUpdateRequest
  ) {
    return this.controlPlaneService.updateCommentDispatchOutboxStatus(outboxItemId, body);
  }
}
