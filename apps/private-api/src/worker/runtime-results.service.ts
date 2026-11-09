import { createHash, randomUUID } from "node:crypto";
import { BadRequestException, ServiceUnavailableException } from "@nestjs/common";
import { MAX_EVIDENCE_TTL_MS } from "@aegisai/shared/private-runtime";
import type { RuntimeResultInput, RuntimeFindingInput, ScanDispatchLease } from "@aegisai/shared/private-runtime";
import { PrismaService } from "../prisma/prisma.service";
import { serializable } from "../prisma/transaction";
import { FetchCapabilityService } from "../token-broker/fetch-capability.service";
import type { EvidenceStorage } from "../data-security/evidence-store";

const VERSIONS={OPENGREP:"1.33.1",TRIVY:"0.76.2",SYFT:"1.57.0"} as const;
const RULES: Record<string,{title:string;severity:string}>={
  "aegisai.java.request-to-process":{title:"Untrusted request input reaches process execution",severity:"HIGH"},
  "aegisai.java.request-to-statement":{title:"Untrusted request input reaches a SQL statement",severity:"HIGH"},
  "aegisai.java.weak-des-cipher":{title:"Weak DES encryption",severity:"MEDIUM"}
};
function invalid(): never {throw new BadRequestException("Invalid reduced runtime result");}
function fields(value: unknown,names: string[]): asserts value is Record<string,unknown> {
  if(!value || typeof value!=="object" || Array.isArray(value) ||
    Object.keys(value).length!==names.length || Object.keys(value).some(key=>!names.includes(key))) invalid();
}
function safePath(value: unknown): value is string {
  return typeof value==="string" && value.length>0 && value.length<=512 &&
    !/[\\:\p{Cc}\p{Cf}]/u.test(value) && value.split("/").every(part=>!!part && part!=="." && part!==".." && part.toLowerCase()!==".git");
}
function line(value: unknown): boolean {return Number.isInteger(value) && Number(value)>0 && Number(value)<=1_000_000;}

/** Reject raw messages/snippets and derive presentation text from trusted rule IDs. */
export function validateRuntimeResult(input: unknown): RuntimeResultInput {
  fields(input,["scannerSetVersion","vulnerabilityDatabaseDigest","runs","findings"]);
  if(typeof input.scannerSetVersion!=="string" || !/^[A-Za-z0-9._:-]{1,200}$/.test(input.scannerSetVersion) ||
    typeof input.vulnerabilityDatabaseDigest!=="string" || !/^sha256:[a-f0-9]{64}$/.test(input.vulnerabilityDatabaseDigest) ||
    !Array.isArray(input.runs) || input.runs.length!==3 || !Array.isArray(input.findings) || input.findings.length>1000) invalid();
  const statuses=new Map<string,string>();
  for(const run of input.runs) {
    fields(run,["scanner","status","durationMs"]);
    if(typeof run.scanner!=="string" || !Object.hasOwn(VERSIONS,run.scanner) || statuses.has(run.scanner) ||
      typeof run.status!=="string" || !["COMPLETED","FAILED","TIMED_OUT","SKIPPED"].includes(run.status) ||
      !Number.isInteger(run.durationMs) || Number(run.durationMs)<0 || Number(run.durationMs)>600_000) invalid();
    statuses.set(run.scanner,String(run.status));
  }
  const seen=new Set<string>();
  for(const finding of input.findings) {
    fields(finding,["scanner","ruleId","severity","filePath","lineStart","lineEnd"]);
    if(typeof finding.scanner!=="string" || !["OPENGREP","TRIVY"].includes(finding.scanner) || statuses.get(finding.scanner)!=="COMPLETED" ||
      typeof finding.ruleId!=="string" || typeof finding.severity!=="string" ||
      !["CRITICAL","HIGH","MEDIUM","LOW","INFO"].includes(finding.severity) || !safePath(finding.filePath)) invalid();
    if(finding.scanner==="OPENGREP") {
      const rule=Object.hasOwn(RULES,finding.ruleId)?RULES[finding.ruleId]:undefined;
      if(!rule || rule.severity!==finding.severity || !finding.filePath.endsWith(".java") ||
        !line(finding.lineStart) || (finding.lineEnd!==null && (!line(finding.lineEnd) || Number(finding.lineEnd)<Number(finding.lineStart)))) invalid();
    } else if(!/^(CVE-[0-9]{4}-[0-9]{4,12}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/.test(finding.ruleId) ||
      finding.lineStart!==null || finding.lineEnd!==null) invalid();
    const fingerprint=JSON.stringify([finding.scanner,finding.ruleId,finding.filePath,finding.lineStart,finding.lineEnd]);
    if(seen.has(fingerprint)) invalid();
    seen.add(fingerprint);
  }
  return input as unknown as RuntimeResultInput;
}

/** Root-only private worker library; deterministic results never depend on AI. */
export class RuntimeResultsService {
  constructor(private readonly prisma: PrismaService,private readonly capabilities: FetchCapabilityService,
    private readonly evidence?:EvidenceStorage) {}

  async start(lease: ScanDispatchLease,credentialId: string): Promise<void> {
    await serializable(this.prisma,async tx=>{
      const {scan,timestamp}=await this.capabilities.requireHandoff(tx,lease,credentialId,true);
      if(scan.status!=="RUNNING") await tx.scanRequest.update({where:{id:scan.id},data:{status:"RUNNING",startedAt:timestamp}});
    });
  }

  async publish(lease: ScanDispatchLease,credentialId: string,value: unknown): Promise<{status:"COMPLETED"|"FAILED";findingCount:number;ai:"DISABLED"}> {
    const input=validateRuntimeResult(value);
    if(!this.evidence) throw new ServiceUnavailableException("Encrypted evidence storage is required");
    const initial=await serializable(this.prisma,tx=>this.capabilities.requireHandoff(tx,lease,credentialId,false));
    if(initial.scan.scannerSetVersion!==input.scannerSetVersion) invalid();
    const scope={tenantId:lease.tenantId,scanRequestId:lease.scanRequestId,id:`evidence_${randomUUID()}`,
      expiresAt:new Date(initial.timestamp.getTime()+MAX_EVIDENCE_TTL_MS)};
    const payload={version:1,evidenceId:scope.id,tenantId:scope.tenantId,scanRequestId:scope.scanRequestId,
      commitSha:initial.scan.commitSha,classification:"SHORT_LIVED_EVIDENCE",redacted:true,aiSafe:true,dashboardSafe:true,
      fragmentCount:0,fragments:[],truncated:false,suppressionApplied:false,ai:"DISABLED",coverage:input.runs.every(run=>run.status==="COMPLETED")?"LIMITED":"UNAVAILABLE",
      expiresAt:scope.expiresAt.toISOString(),scannerSetVersion:input.scannerSetVersion,
      vulnerabilityDatabaseDigest:input.vulnerabilityDatabaseDigest,runs:input.runs,findings:input.findings};
    const artifact=await this.evidence.put(scope,payload);
    try {return await serializable(this.prisma,async tx=>{
      const {scan,timestamp}=await this.capabilities.requireHandoff(tx,lease,credentialId,false);
      if(scan.scannerSetVersion!==input.scannerSetVersion) invalid();
      const runIds=new Map(input.runs.map(run=>[run.scanner,`scanner_run_${randomUUID()}`]));
      const allCompleted=input.runs.every(run=>run.status==="COMPLETED");
      for(const run of input.runs) {
        await tx.scannerRun.create({data:{id:runIds.get(run.scanner)!,tenantId:scan.tenantId,scanRequestId:scan.id,
          scanner:run.scanner,scannerVersion:VERSIONS[run.scanner],status:run.status,startedAt:scan.startedAt,completedAt:timestamp,
          coverageState:{state:run.status==="COMPLETED"?"LIMITED":"UNAVAILABLE",durationMs:run.durationMs,
            scope:run.scanner==="OPENGREP"?"INITIAL_JAVA_RULES":"DECLARED_DEPENDENCIES_ONLY",
            vulnerabilityDatabaseDigest:input.vulnerabilityDatabaseDigest,ai:"DISABLED"}}});
      }
      if(input.findings.length) await tx.normalizedFinding.createMany({data:input.findings.map((finding: RuntimeFindingInput)=>({
        id:"finding_"+createHash("sha256").update(JSON.stringify([scan.id,finding])).digest("hex"),
        tenantId:scan.tenantId,scanRequestId:scan.id,scannerRunId:runIds.get(finding.scanner)!,
        title:finding.scanner==="OPENGREP"?RULES[finding.ruleId].title:`Dependency advisory ${finding.ruleId}`,
        severity:finding.severity,scannerProvenance:finding.scanner,filePath:finding.filePath,
        lineStart:finding.lineStart,lineEnd:finding.lineEnd,metadata:{ruleId:finding.ruleId,ai:"DISABLED"}
      }))});
      const review=input.findings.some(finding=>["CRITICAL","HIGH"].includes(finding.severity));
      await tx.policyDecision.create({data:{tenantId:scan.tenantId,scanRequestId:scan.id,
        enforcementAction:review||!allCompleted?"WARN":"DASHBOARD_ONLY",commentAllowed:false,blockRequested:false,
        aiAdvisoryVisible:false,reasonCodes:["LIMITED_COVERAGE",...(review?["REVIEW_REQUIRED"]:[]),...(!allCompleted?["SCANNER_UNAVAILABLE"]:[])],
        requiredCoverage:{state:allCompleted?"LIMITED":"UNAVAILABLE",mergeEnforced:false,ai:"DISABLED"}}});
      await tx.evidencePack.create({data:{...scope,objectKey:artifact.objectKey,byteSize:artifact.byteSize,redacted:true}});
      const status=allCompleted?"COMPLETED" as const:"FAILED" as const;
      await tx.scanRequest.update({where:{id:scan.id},data:{status,completedAt:timestamp}});
      // Dispatch succeeded means this bounded result was delivered durably, even
      // when the recorded scan itself failed. Never retry a terminal result.
      await tx.scanDispatchJob.update({where:{id:lease.jobId},data:{status:"SUCCEEDED",leaseToken:null,leasedBy:null,leaseExpiresAt:null}});
      await tx.auditEvent.create({data:{tenantId:scan.tenantId,scanRequestId:scan.id,eventType:"scan.runtime.published",
        actor:"private-runtime",targetType:"scan_request",targetId:scan.id,
        metadata:{attempt:lease.attempt,status,findingCount:input.findings.length,ai:"DISABLED"}}});
      return {status,findingCount:input.findings.length,ai:"DISABLED"};
    });} catch(error) {
      // A lost commit acknowledgement is ambiguous. Never delete an object
      // referenced by a committed row; leave unknown state for scheduled cleanup.
      const persisted=await this.prisma.evidencePack.findUnique({where:{id:scope.id},select:{id:true}}).catch(()=>undefined);
      if(persisted===null) await this.evidence.remove(artifact.objectKey).catch(()=>undefined);
      throw error;
    }
  }
}
