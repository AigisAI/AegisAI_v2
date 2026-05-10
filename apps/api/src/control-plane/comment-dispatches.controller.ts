import { Body, Controller, Get, Post, Query } from "@nestjs/common";

import type { CommentDispatchEnqueueRequest, CommentDispatchPlanRequest } from "../../../../packages/shared/src";
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
  listOutbox(@Query("tenantId") tenantId: string) {
    return this.controlPlaneService.listCommentDispatchOutbox(tenantId);
  }
}
