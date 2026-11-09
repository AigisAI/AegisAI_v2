import { assertPrivateDatabase } from "./private-profile";
import { spawnSync } from "node:child_process";
import { loadRuntimeSecrets } from "./runtime-secrets";

async function main() {
  await loadRuntimeSecrets("data");
  await assertPrivateDatabase();
  if(process.env.NODE_ENV!=="production" || new URL(process.env.DATABASE_URL??"").pathname!=="/aegisai") throw new Error();
  const result=spawnSync('corepack',['pnpm','--filter','@aegisai/private-api','prisma:migrate:deploy'],{stdio:'inherit',env:process.env});
  process.exit(result.status??1);
}
void main().catch(()=>{process.stderr.write('MANAGED_MIGRATION_FAILED\n');process.exit(1);});
