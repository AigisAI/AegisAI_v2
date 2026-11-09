import { Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import type { RuntimeScanDetail, RuntimeScanSummary } from "@aegisai/shared/private-runtime";
import type { AuthenticatedPrincipal } from "../auth/auth.types";
import { ControlPlaneService } from "../control-plane/control-plane.service";
import { GithubAppClient } from "../control-plane/github-app.client";
import { PrismaService } from "../prisma/prisma.service";
import { RuntimeCatalogService } from "./runtime-catalog.service";

const selection={id:true,status:true,repositoryBindingId:true,targetRef:true,commitSha:true,createdAt:true,startedAt:true,completedAt:true,
  repositoryBinding:{select:{fullName:true}}} as const;
type ScanRow={id:string;status:RuntimeScanSummary["status"];repositoryBindingId:string;targetRef:string;commitSha:string;
  createdAt:Date;startedAt:Date|null;completedAt:Date|null;repositoryBinding:{fullName:string}};
function summary(row:ScanRow): RuntimeScanSummary {
  return {id:row.id,status:row.status,repositoryBindingId:row.repositoryBindingId,repositoryName:row.repositoryBinding.fullName,
    branch:row.targetRef,commitSha:row.commitSha,createdAt:row.createdAt.toISOString(),startedAt:row.startedAt?.toISOString()??null,
    completedAt:row.completedAt?.toISOString()??null};
}

@Injectable()
export class RuntimeApiService {
  constructor(private readonly prisma:PrismaService,private readonly control:ControlPlaneService,
    private readonly github:GithubAppClient,private readonly catalog:RuntimeCatalogService) {}

  async create(principal:AuthenticatedPrincipal,repositoryBindingId:string,branch?:string) {
    const status=await this.catalog.read();
    if(!status.ready) throw new ServiceUnavailableException({errorCode:"PRODUCTION_RUNTIME_NOT_READY",message:"The private scanner is unavailable. Existing results remain readable."});
    const binding=await this.prisma.repositoryBinding.findFirst({where:{id:repositoryBindingId,tenantId:principal.tenantId,
      tenant:{status:"ACTIVE"},integration:{tenantId:principal.tenantId,status:"ACTIVE",provider:"GITHUB"}},include:{integration:true}});
    if(!binding || binding.fullName.split("/")[0].toLowerCase()!=="aigisai") throw new NotFoundException("Active private organization repository not found");
    const targetRef=branch??binding.defaultBranch;
    const resolved=await this.github.resolveBranchCommit(Number(binding.integration.externalInstallationId),Number(binding.providerRepoId),principal.providerUserId,targetRef);
    // Provider metadata resolution/revocation must finish before queue insertion.
    const current=await this.catalog.read();
    if(!current.ready || current.scannerSetVersion!==status.scannerSetVersion) throw new ServiceUnavailableException("Scanner configuration changed; retry the request");
    return this.control.createScanRequest({tenantId:principal.tenantId,repositoryBindingId:binding.id,lane:"FAST",targetRef,
      commitSha:resolved.commitSha,policyVersion:status.policyVersion!,scannerSetVersion:status.scannerSetVersion!},3);
  }

  async list(tenantId:string):Promise<RuntimeScanSummary[]> {
    return (await this.prisma.scanRequest.findMany({where:{tenantId,tenant:{status:"ACTIVE"}},select:selection,
      orderBy:{createdAt:"desc"},take:50})).map(summary);
  }

  async detail(tenantId:string,scanRequestId:string):Promise<RuntimeScanDetail> {
    const scan=await this.prisma.scanRequest.findFirst({where:{id:scanRequestId,tenantId,tenant:{status:"ACTIVE"}},select:selection});
    if(!scan) throw new NotFoundException("Scan request not found");
    const [runs,findings,policy,rejection,evidence]=await Promise.all([
      this.prisma.scannerRun.findMany({where:{tenantId,scanRequestId},orderBy:{scanner:"asc"},take:3}),
      this.prisma.normalizedFinding.findMany({where:{tenantId,scanRequestId},orderBy:[{severity:"asc"},{filePath:"asc"}],take:1000}),
      this.prisma.policyDecision.findFirst({where:{tenantId,scanRequestId},orderBy:{createdAt:"desc"}}),
      this.prisma.auditEvent.findFirst({where:{tenantId,scanRequestId,eventType:"scan.runtime.rejected"},orderBy:{occurredAt:"desc"},select:{metadata:true}}),
      this.prisma.evidencePack.findFirst({where:{tenantId,scanRequestId},orderBy:{createdAt:"desc"},select:{expiresAt:true,deletedAt:true}})
    ]);
    const failureReason=rejection?.metadata && typeof rejection.metadata==="object" && !Array.isArray(rejection.metadata) && typeof rejection.metadata.reason==="string"?rejection.metadata.reason:null;
    return {...summary(scan),ai:"DISABLED",failureReason,evidence:evidence?{available:!evidence.deletedAt&&evidence.expiresAt.getTime()>Date.now(),expiresAt:evidence.expiresAt.toISOString()}:null,
      coverage:runs.length===0?(scan.status==="FAILED"||scan.status==="CANCELED"?"UNAVAILABLE":"PENDING"):runs.length===3 && runs.every(run=>run.status==="COMPLETED")?"LIMITED":"UNAVAILABLE",
      runs:runs.filter(run=>run.scanner!=="MOCK").map(run=>({scanner:run.scanner as "OPENGREP"|"TRIVY"|"SYFT",status:run.status,scannerVersion:run.scannerVersion})),
      findings:findings.filter(finding=>["OPENGREP","TRIVY"].includes(finding.scannerProvenance)).map(finding=>({
        id:finding.id,title:finding.title,status:finding.status,scanner:finding.scannerProvenance as "OPENGREP"|"TRIVY",
        ruleId:typeof finding.metadata==="object" && finding.metadata && !Array.isArray(finding.metadata) && typeof finding.metadata.ruleId==="string"?finding.metadata.ruleId:"",
        severity:finding.severity,filePath:finding.filePath,lineStart:finding.lineStart,lineEnd:finding.lineEnd})),
      policy:policy?{action:policy.enforcementAction,reasonCodes:Array.isArray(policy.reasonCodes)?policy.reasonCodes.filter((code):code is string=>typeof code==="string"):[],mergeEnforced:false}:null};
  }
}
