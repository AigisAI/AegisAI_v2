/** Operator-only synthetic metadata probe. Creates no product identity or scan. */
import { randomUUID } from "node:crypto";
import { PrismaService } from "../prisma/prisma.service";
import { loadRuntimeSecrets } from "./runtime-secrets";
import { S3EvidenceStore } from "./evidence-store";
import { enforceEvidenceExpiry } from "./evidence-maintenance";

async function main() {
  await loadRuntimeSecrets("data");
  if(process.env.NODE_ENV!=="production" || new URL(process.env.DATABASE_URL??"").pathname!=="/aegisai") throw new Error();
  const store=S3EvidenceStore.fromEnvironment(),prisma=new PrismaService();
  const scope={tenantId:"tenant_ops",scanRequestId:"scan_ops",id:"evidence_ops_"+randomUUID().replaceAll('-',''),expiresAt:new Date(Date.now()+3000)};
  let key:string|undefined;
  try {
    const before=await prisma.scanRequest.count();
    const payload={version:1,tenantId:scope.tenantId,scanRequestId:scope.scanRequestId,evidenceId:scope.id,
      redacted:true,classification:"SHORT_LIVED_EVIDENCE",sourceProcessed:false,purpose:"infrastructure-retention-probe"};
    const artifact=await store.put(scope,payload);key=artifact.objectKey;
    const head=await store.describe(key);
    if(head.ServerSideEncryption!=="aws:kms" || head.SSEKMSKeyId!==process.env.EVIDENCE_KMS_KEY_ARN || head.BucketKeyEnabled===true) throw new Error();
    const bytes=await store.read(scope,key);
    if(JSON.parse(bytes.toString()).purpose!==payload.purpose) throw new Error();
    await new Promise(resolve=>setTimeout(resolve,Math.max(1,scope.expiresAt.getTime()-Date.now()+500)));
    const enforcement=await enforceEvidenceExpiry(prisma,store);
    if(enforcement.orphansDeleted<1) throw new Error();
    let missing=false;
    try {await store.describe(key);} catch(error) {missing=(error as {$metadata?:{httpStatusCode?:number}}).$metadata?.httpStatusCode===404;}
    if(!missing || await prisma.scanRequest.count()!==before) throw new Error();
    process.stdout.write(JSON.stringify({managedKmsRoundTrip:"passed",tenantScopedMetadata:"verified",scheduledExpiryCode:"passed",
      expiredObjectAbsent:true,productScanCreated:false,customerSourceProcessed:false})+'\n');
  } finally {
    if(key) await store.remove(key).catch(()=>undefined);
    await prisma.$disconnect();
  }
}
void main().catch(()=>{process.stderr.write('MANAGED_STORAGE_PROBE_FAILED\n');process.exit(1);});
