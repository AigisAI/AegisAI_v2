import { Body, Controller, Get, Param, Post, Req, Res, UseGuards } from "@nestjs/common";
import type { Response } from "express";
import { EvidenceAccessService } from "../data-security/evidence-access.service";
import { Throttle } from "@nestjs/throttler";
import { IsOptional, IsString, Length, Matches } from "class-validator";
import type { AuthenticatedRequest } from "../auth/auth.types";
import { CurrentTenant } from "../common/security/current-tenant.decorator";
import { SessionAuthGuard } from "../common/security/session-auth.guard";
import { ScanRequestIdParamDto } from "../control-plane/control-plane.dto";
import { ControlPlaneService } from "../control-plane/control-plane.service";
import { RuntimeApiService } from "./runtime-api.service";
import { RuntimeCatalogService } from "./runtime-catalog.service";

export class CreateRuntimeScanDto {
  @IsString() @Matches(/^[A-Za-z0-9_-]{1,128}$/) repositoryBindingId!:string;
  @IsOptional() @IsString() @Length(1,255) branch?:string;
}

@Controller("runtime")
@UseGuards(SessionAuthGuard)
export class RuntimeController {
  constructor(private readonly runtime:RuntimeApiService,private readonly catalog:RuntimeCatalogService,private readonly control:ControlPlaneService,private readonly evidence:EvidenceAccessService) {}
  @Get("status") status() {return this.catalog.read();}
  @Get("repositories") repositories(@CurrentTenant() tenantId:string) {return this.control.listRepositoryBindings(tenantId);}
  @Get("scans") list(@CurrentTenant() tenantId:string) {return this.runtime.list(tenantId);}
  @Get("scans/:scanRequestId") detail(@CurrentTenant() tenantId:string,@Param() params:ScanRequestIdParamDto) {
    return this.runtime.detail(tenantId,params.scanRequestId);
  }
  @Get("scans/:scanRequestId/evidence")
  async readEvidence(@Req() request:AuthenticatedRequest,@Param() params:ScanRequestIdParamDto,@Res({passthrough:true}) response:Response) {
    const bytes=await this.evidence.read(request.auth!.tenantId,params.scanRequestId,request.auth!.userId);
    response.setHeader('Content-Type','application/json');response.setHeader('Content-Disposition','attachment; filename="evidence.json"');
    return bytes;
  }
  @Post("scans")
  @Throttle({default:{limit:5,ttl:60_000}})
  create(@Req() request:AuthenticatedRequest,@Body() body:CreateRuntimeScanDto) {
    return this.runtime.create(request.auth!,body.repositoryBindingId,body.branch);
  }
}
