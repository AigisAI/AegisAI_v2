import { Body, Controller, Get, Param, Patch, Post, Query } from "@nestjs/common";

import type {
  CommentDispatchEnqueueRequest,
  CommentDispatchOutboxClaimRequest,
  CommentDispatchOutboxListQuery,
  CommentDispatchOutboxLeaseRenewalRequest,
  CommentDispatchOutboxStatusUpdateRequest,
  CommentDispatchPlanRequest
} from "../../../../packages/shared/src";
import { ControlPlaneService } from "./control-plane.service";

@Controller("comment-dispatches")
export class CommentDispatchesController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post("plan")
  plan(@Body() body: CommentDispatchPlanRequest) {
    return this.controlPlaneService.planCommentDispatch(body);
  }

  @Post("enqueue")
  enqueue(@Body() body: CommentDispatchEnqueueRequest) {
    return this.controlPlaneService.enqueueCommentDispatch(body);
  }

  @Get("audit-events")
  listAuditEvents(@Query("tenantId") tenantId: string) {
    return this.controlPlaneService.listCommentDispatchAuditEvents(tenantId);
  }

  @Get("outbox")
  listOutbox(@Query() query: CommentDispatchOutboxListQuery) {
    return this.controlPlaneService.listCommentDispatchOutbox(query);
  }

  @Post("outbox/claim")
  claimOutbox(@Body() body: CommentDispatchOutboxClaimRequest) {
    return this.controlPlaneService.claimCommentDispatchOutbox(body);
  }

  @Patch("outbox/:outboxItemId/lease")
  renewOutboxLease(
    @Param("outboxItemId") outboxItemId: string,
    @Body() body: CommentDispatchOutboxLeaseRenewalRequest
  ) {
    return this.controlPlaneService.renewCommentDispatchOutboxLease(outboxItemId, body);
  }

  @Patch("outbox/:outboxItemId/status")
  updateOutboxStatus(
    @Param("outboxItemId") outboxItemId: string,
    @Body() body: CommentDispatchOutboxStatusUpdateRequest
  ) {
    return this.controlPlaneService.updateCommentDispatchOutboxStatus(outboxItemId, body);
  }
}
