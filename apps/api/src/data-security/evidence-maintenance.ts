import type { PrismaService } from "../prisma/prisma.service";
import type { S3EvidenceStore } from "./evidence-store";

export interface RetentionStatus {healthy:boolean;checkedAt:string;deleted:number;orphansDeleted:number;oldestExpiredSeconds:number;}

/** Scheduled deletion with retries on the next cycle, not S3 lifecycle alone. */
export async function enforceEvidenceExpiry(prisma:PrismaService,store:S3EvidenceStore):Promise<RetentionStatus> {
  const [{now}]=await prisma.$queryRaw<{now:Date}[]>`SELECT clock_timestamp() AS now`;
  const expired=await prisma.evidencePack.findMany({where:{deletedAt:null,expiresAt:{lte:now}},orderBy:{expiresAt:"asc"},take:1000});
  let deleted=0,orphansDeleted=0;
  for(const evidence of expired) {
    await store.remove(evidence.objectKey);
    await prisma.$transaction(async tx=>{
      const updated=await tx.evidencePack.updateMany({where:{id:evidence.id,tenantId:evidence.tenantId,deletedAt:null,expiresAt:{lte:now}},data:{deletedAt:now}});
      if(updated.count) await tx.auditEvent.create({data:{tenantId:evidence.tenantId,scanRequestId:evidence.scanRequestId,
        eventType:"evidence.expired.deleted",actor:"evidence-retention",targetType:"evidence_pack",targetId:evidence.id}});
    });
    deleted++;
  }
  let token:string|undefined;
  for(let page=0;page<10;page++) {
    const objects=await store.inventory(token);
    const keys=(objects.Contents??[]).map(item=>item.Key).filter((key):key is string=>!!key);
    const referenced=await prisma.evidencePack.findMany({where:{objectKey:{in:keys}},select:{objectKey:true}});
    const known=new Set(referenced.map(row=>row.objectKey));
    for(const object of objects.Contents??[]) {
      if(!object.Key || known.has(object.Key)) continue;
      const head=await store.describe(object.Key);
      const expiry=Date.parse(head.Metadata?.['expires-at']??'');
      const old=!!object.LastModified&&now.getTime()-object.LastModified.getTime()>3600_000;
      if(old || Number.isFinite(expiry)&&expiry<=now.getTime()) {
        await store.remove(object.Key);orphansDeleted++;
      }
    }
    token=objects.NextContinuationToken;
    if(!token) break;
    if(page===9) throw new Error("EVIDENCE_INVENTORY_CAPACITY_EXCEEDED");
  }
  const oldest=await prisma.evidencePack.findFirst({where:{deletedAt:null,expiresAt:{lte:now}},orderBy:{expiresAt:"asc"},select:{expiresAt:true}});
  const lag=oldest?Math.max(0,Math.floor((now.getTime()-oldest.expiresAt.getTime())/1000)):0;
  return {healthy:lag<=86400,checkedAt:now.toISOString(),deleted,orphansDeleted,oldestExpiredSeconds:lag};
}
