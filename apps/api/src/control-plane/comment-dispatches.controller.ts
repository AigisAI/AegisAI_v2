import { Body, Controller, Get, Post, Query } from "@nestjs/common";

import type { CommentDispatchPlanRequest } from "../../../../packages/shared/src";
import { ControlPlaneService } from "./control-plane.service";

@Controller("comment-dispatches")
export class CommentDispatchesController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post("plan")
  plan(@Body() body: CommentDispatchPlanRequest) {
    return this.controlPlaneService.planCommentDispatch(body);
  }

  @Get("audit-events")
  listAuditEvents(@Query("tenantId") tenantId: string) {
    return this.controlPlaneService.listCommentDispatchAuditEvents(tenantId);
  }
}
