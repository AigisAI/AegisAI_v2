import { writeFile, rename } from "node:fs/promises";
import { PrismaService } from "../prisma/prisma.service";
import { loadRuntimeSecrets } from "./runtime-secrets";
import { S3EvidenceStore } from "./evidence-store";
import { enforceEvidenceExpiry } from "./evidence-maintenance";

async function main() {
  await loadRuntimeSecrets("data");
  if(process.env.NODE_ENV!=="production" || new URL(process.env.DATABASE_URL??"").pathname!=="/aegisai") throw new Error();
  const prisma=new PrismaService();
  try {
    const status=await enforceEvidenceExpiry(prisma,S3EvidenceStore.fromEnvironment());
    await writeFile('/run/retention/status.pending.json',JSON.stringify(status),{mode:0o644});
    await rename('/run/retention/status.pending.json','/run/retention/status.json');
    if(!status.healthy) throw new Error();
    process.stdout.write('EVIDENCE_RETENTION_ENFORCED\n');
  } finally {await prisma.$disconnect();}
}
void main().catch(async()=>{
  try {
    await writeFile('/run/retention/status.pending.json',JSON.stringify({healthy:false,checkedAt:new Date().toISOString(),oldestExpiredSeconds:86401}),{mode:0o644});
    await rename('/run/retention/status.pending.json','/run/retention/status.json');
  } catch { /* missing or stale status also blocks admission */ }
  process.stderr.write('EVIDENCE_RETENTION_ALERT\n');process.exit(1);
});
