import { ConfigService as NestConfigService } from "@nestjs/config";
import { ConfigService } from "../config/config.service";
import { GithubAppClient } from "../control-plane/github-app.client";
import { PrismaService } from "../prisma/prisma.service";
import { PrivateWorkerBroker } from "./private-worker-broker";
import { loadRuntimeSecrets } from "../data-security/runtime-secrets";
import { S3EvidenceStore } from "../data-security/evidence-store";

/** Separate container entrypoint. The ordinary API never starts this server. */
async function main(): Promise<void> {
  await loadRuntimeSecrets("broker");
  const value=process.env.DATABASE_URL;
  if(!value || new URL(value).pathname!=="/aegisai" || process.env.NODE_ENV!=="production") {
    throw new Error("PRIVATE_BROKER_CONFIGURATION_REQUIRED");
  }
  const config=new ConfigService(new NestConfigService(process.env));
  for(const key of ["GITHUB_APP_ID","GITHUB_APP_PRIVATE_KEY_PEM","ALLOWED_GITHUB_USER_IDS"] as const) {
    if(!config.getOptional(key)) throw new Error("PRIVATE_BROKER_CONFIGURATION_REQUIRED");
  }
  const prisma=new PrismaService();
  await prisma.$connect();
  let closing=false;
  const broker=new PrivateWorkerBroker(prisma,config,new GithubAppClient(config),"/run/broker",50001,()=>{void close(1);},S3EvidenceStore.fromEnvironment());
  await broker.start();
  async function close(exitCode=0) {
    if(closing) return;
    closing=true;
    let failed=false;
    try {await broker.close();} catch {failed=true;}
    await prisma.$disconnect();
    process.exit(failed?1:exitCode);
  }
  process.once("SIGTERM",()=>{void close();});
  process.once("SIGINT",()=>{void close();});
  // Fixed operational event only; no request, secret, provider body or source log.
  process.stdout.write("PRIVATE_BROKER_READY\n");
}

if(require.main===module) {
  void main().catch(()=>{process.stderr.write("PRIVATE_BROKER_START_FAILED\n");process.exit(1);});
}
