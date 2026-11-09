import { GoneException, Injectable, NotFoundException } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { S3EvidenceStore, type EvidenceStorage } from "./evidence-store";

@Injectable()
export class EvidenceAccessService {
  private storage?:EvidenceStorage;
  constructor(private readonly prisma:PrismaService) {}
  protected store():EvidenceStorage {return this.storage??=S3EvidenceStore.fromEnvironment();}
  async read(tenantId:string,scanRequestId:string,userId:string):Promise<Buffer> {
    const evidence=await this.prisma.evidencePack.findFirst({where:{tenantId,scanRequestId,tenant:{status:"ACTIVE"}},orderBy:{createdAt:"desc"}});
    if(!evidence) throw new NotFoundException("Evidence not found");
    const time=()=>this.prisma.$queryRaw<{now:Date}[]>`SELECT clock_timestamp() AS now`;
    if(evidence.deletedAt || evidence.expiresAt<=(await time())[0].now) throw new GoneException("Evidence has expired");
    const bytes=await this.store().read(evidence,evidence.objectKey);
    try {await this.prisma.$transaction(async tx=>{
      const [{now}]=await tx.$queryRaw<{now:Date}[]>`SELECT clock_timestamp() AS now`;
      if(!await tx.evidencePack.findFirst({where:{id:evidence.id,tenantId,deletedAt:null,expiresAt:{gt:now},tenant:{status:"ACTIVE"}}})) throw new GoneException("Evidence is expired or no longer accessible");
      await tx.auditEvent.create({data:{tenantId,scanRequestId,eventType:"evidence.read",actor:userId,
        targetType:"evidence_pack",targetId:evidence.id,metadata:{classification:"SHORT_LIVED_EVIDENCE"}}});
    });} catch(error) {bytes.fill(0);throw error;}
    return bytes;
  }
}
