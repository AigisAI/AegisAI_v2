import { timingSafeEqual } from "node:crypto";
import { chmod, lstat, realpath, unlink } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createConnection } from "node:net";
import { join } from "node:path";
import type { FetchGatewayClaim, FetchGatewayCompletion, ScanDispatchLease } from "@aegisai/shared";
import { RUNTIME_REJECTION_REASONS, type RuntimeRejectionReason } from "@aegisai/shared";
import { ConfigService } from "../config/config.service";
import { ControlPlaneService } from "../control-plane/control-plane.service";
import { GithubAppClient } from "../control-plane/github-app.client";
import type { GithubReadSession } from "../control-plane/github-read-session";
import { ScanDispatchService } from "../dispatch/scan-dispatch.service";
import { PrismaService } from "../prisma/prisma.service";
import { FetchCapabilityService } from "../token-broker/fetch-capability.service";
import { RuntimeResultsService } from "./runtime-results.service";
import type { EvidenceStorage } from "../data-security/evidence-store";

type RecordValue = Record<string, unknown>;
type Role = "worker" | "gateway";
interface OpenSession {
  claim: FetchGatewayClaim;
  response: ServerResponse;
  resource?: Promise<GithubReadSession>;
  timer?: ReturnType<typeof setTimeout>;
  finishing?: Promise<FetchGatewayCompletion>;
  canceled: boolean;
}
class RpcFailure extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}
function record(value: unknown): RecordValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new RpcFailure(400,"INVALID_REQUEST");
  return value as RecordValue;
}
function keys(value: RecordValue, expected: string[]): void {
  if (Object.keys(value).length !== expected.length || Object.keys(value).some(key=>!expected.includes(key))) {
    throw new RpcFailure(400,"INVALID_REQUEST");
  }
}
function text(value: unknown, maximum=128): string {
  if (typeof value !== "string" || !value || value.length>maximum || /[\p{Cc}]/u.test(value)) throw new RpcFailure(400,"INVALID_REQUEST");
  return value;
}
function lease(value: unknown): ScanDispatchLease {
  const data=record(value);
  keys(data,["jobId","tenantId","scanRequestId","attempt","leaseToken","expiresAt"]);
  if (!Number.isInteger(data.attempt) || Number(data.attempt)<1 || Number(data.attempt)>5) throw new RpcFailure(400,"INVALID_REQUEST");
  const expiresAt=text(data.expiresAt,64);
  if (!Number.isFinite(Date.parse(expiresAt))) throw new RpcFailure(400,"INVALID_REQUEST");
  return {jobId:text(data.jobId),tenantId:text(data.tenantId),scanRequestId:text(data.scanRequestId),
    attempt:Number(data.attempt),leaseToken:text(data.leaseToken),expiresAt};
}
function equalSecret(one: string,two: string): boolean {
  const first=Buffer.from(one),second=Buffer.from(two);
  return first.length===second.length && timingSafeEqual(first,second);
}
async function body(request: IncomingMessage,maximum=16384): Promise<RecordValue> {
  const chunks: Buffer[]=[];
  let size=0;
  const timer=setTimeout(()=>request.destroy(),10_000);
  try {
    for await (const value of request) {
      const chunk=Buffer.from(value);
      size+=chunk.length;
      if(size>maximum) throw new RpcFailure(413,"REQUEST_TOO_LARGE");
      chunks.push(chunk);
    }
    try { return record(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
    catch { throw new RpcFailure(400,"INVALID_REQUEST"); }
  } finally { clearTimeout(timer); }
}
function reply(response: ServerResponse,status: number,value: unknown): void {
  if(response.destroyed || response.writableEnded) return;
  response.writeHead(status,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"});
  response.end(JSON.stringify(value));
}
async function liveSocket(path: string): Promise<boolean> {
  return new Promise((resolve,reject)=>{
    const socket=createConnection(path);
    socket.setTimeout(1000);
    socket.once("connect",()=>{socket.destroy();resolve(true);});
    socket.once("timeout",()=>{socket.destroy();reject(new Error("SOCKET_PROBE_UNCONFIRMED"));});
    socket.once("error",(error: NodeJS.ErrnoException)=>{
      socket.destroy();
      if(["ENOENT","ECONNREFUSED"].includes(error.code || "")) resolve(false); else reject(new Error("SOCKET_PROBE_UNCONFIRMED"));
    });
  });
}

/** Explicit private control process only. Never imported as an application HTTP controller. */
export class PrivateWorkerBroker {
  private readonly capabilities: FetchCapabilityService;
  private readonly queue: ScanDispatchService;
  private readonly control: ControlPlaneService;
  private readonly results: RuntimeResultsService;
  private readonly sessions=new Map<string,OpenSession>();
  private readonly servers: Server[]=[];
  private readonly socketInodes=new Map<string,number>();
  private ready=false;
  private finalizationFailed=false;

  constructor(private readonly prisma: PrismaService,config: ConfigService,
    private readonly provider: Pick<GithubAppClient,"openReadSession">,
    private readonly directory: string,private readonly gatewayGid=50001,private readonly onFatal?:()=>void,
    private readonly evidence?:EvidenceStorage) {
    this.capabilities=new FetchCapabilityService(prisma,config);
    this.queue=new ScanDispatchService(prisma);
    this.control=new ControlPlaneService(prisma);
    this.results=new RuntimeResultsService(prisma,this.capabilities,evidence);
  }

  private unhealthy(): void {
    const wasReady=this.ready;
    this.ready=false;
    this.finalizationFailed=true;
    if(wasReady) {try {this.onFatal?.();} catch { /* authority stays closed */ }}
  }

  async start(): Promise<void> {
    if(!this.evidence) throw new Error("ENCRYPTED_EVIDENCE_STORAGE_REQUIRED");
    const info=await lstat(this.directory);
    if(process.getuid?.()!==0 || !info.isDirectory() || info.isSymbolicLink() || info.uid!==0 ||
        info.gid!==this.gatewayGid || (info.mode&0o027)!==0 || !(info.mode&0o2000) ||
        await realpath(this.directory)!==this.directory) throw new Error("PRIVATE_SOCKET_DIRECTORY_REQUIRED");
    const paths=[join(this.directory,"control.sock"),join(this.directory,"gateway.sock")];
    for(const path of paths) {
      try {
        const old=await lstat(path);
        if(!old.isSocket() || old.uid!==0 || await liveSocket(path)) throw new Error("BROKER_ALREADY_RUNNING");
        await unlink(path);
      } catch(error) {
        if((error as NodeJS.ErrnoException).code!=="ENOENT") throw error;
      }
    }
    try {
      for(const [index,role] of (["worker","gateway"] as const).entries()) {
        const server=createServer({maxHeaderSize:8192},(request,response)=>{
          void this.handle(role,request,response).catch(error=>{
            const status=error instanceof RpcFailure ? error.status : typeof error?.getStatus==="function" ? error.getStatus() : 503;
            const code=error instanceof RpcFailure ? error.code : status===403 ? "FORBIDDEN" : status===409 ? "AUTHORITY_LOST" : "BROKER_UNAVAILABLE";
            if(response.headersSent) response.destroy(); else reply(response,status,{ok:false,errorCode:code});
          });
        });
        server.headersTimeout=5000;
        server.requestTimeout=10000;
        server.keepAliveTimeout=1000;
        server.maxConnections=16;
        server.on("error",()=>{if(this.ready)this.unhealthy();});
        this.servers.push(server);
        const previous=process.umask(0o077);
        try {
          await new Promise<void>((resolve,reject)=>{
            server.once("error",reject);
            server.listen({path:paths[index]},()=>{server.off("error",reject);resolve();});
          });
        } finally {process.umask(previous);}
        this.socketInodes.set(paths[index],(await lstat(paths[index])).ino);
        await chmod(paths[index],role==="worker"?0o600:0o660);
        if((await lstat(paths[index])).gid!==this.gatewayGid) throw new Error("PRIVATE_SOCKET_GROUP_REQUIRED");
      }
      // Bind first: a duplicate process cannot rotate a live broker's epoch.
      await this.capabilities.startEpoch();
      this.ready=true;
    } catch(error) { await this.close(); throw error; }
  }

  private async handle(role: Role,request: IncomingMessage,response: ServerResponse): Promise<void> {
    if(request.method==="GET" && request.url==="/health") {
      const healthy=this.ready && await this.capabilities.healthy().catch(()=>false) && await this.evidence!.healthy();
      reply(response,healthy?200:503,{ok:healthy});return;
    }
    if(!this.ready) throw new RpcFailure(503,"BROKER_UNAVAILABLE");
    if(request.method!=="POST") throw new RpcFailure(405,"METHOD_NOT_ALLOWED");
    if(request.headers["content-type"]?.split(";")[0]!=="application/json") throw new RpcFailure(415,"INVALID_REQUEST");
    const data=await body(request,role==="worker" && request.url==="/worker/publish"?1024*1024:16384);
    request.setTimeout(0);
    const path=request.url;
    if(role==="worker") {
      if(path==="/worker/reject") {
        keys(data,["lease","reason"]);const owned=lease(data.lease);
        if(!RUNTIME_REJECTION_REASONS.includes(data.reason as RuntimeRejectionReason)) throw new RpcFailure(400,"INVALID_REQUEST");
        await this.queue.reject(owned.tenantId,owned.jobId,owned.leaseToken,data.reason as RuntimeRejectionReason);
        reply(response,200,{ok:true,data:null});return;
      }
      if(path==="/worker/start" || path==="/worker/publish") {
        keys(data,path==="/worker/start"?["lease","credentialId"]:["lease","credentialId","result"]);
        const owned=lease(data.lease),credentialId=text(data.credentialId);
        const result=path==="/worker/start"?await this.results.start(owned,credentialId):
          await this.results.publish(owned,credentialId,data.result);
        reply(response,200,{ok:true,data:result??null});return;
      }
      if(path==="/worker/claim") {
        keys(data,["workerId"]);
        if(!await this.evidence!.healthy()) throw new RpcFailure(503,"EVIDENCE_STORAGE_UNAVAILABLE");
        const owned=await this.queue.claim(text(data.workerId),this.capabilities.admittedTenantIds());
        if(!owned) {reply(response,200,{ok:true,data:null});return;}
        const scan=await this.control.getScanRequest(owned.tenantId,owned.scanRequestId);
        const {id,tenantId,repositoryBindingId,commitSha,targetRef,policyVersion,scannerSetVersion,isolationClass}=scan;
        reply(response,200,{ok:true,data:{lease:owned,execution:{id,tenantId,repositoryBindingId,commitSha,targetRef,policyVersion,scannerSetVersion,isolationClass}}});return;
      }
      if(path==="/worker/capability" || path==="/worker/heartbeat") {
        keys(data,["lease"]);const owned=lease(data.lease);
        const result=path==="/worker/capability" ? await this.capabilities.issue(owned) :
          await this.queue.heartbeat(owned.tenantId,owned.jobId,owned.leaseToken);
        reply(response,200,{ok:true,data:result});return;
      }
      if(path==="/worker/fail") {
        keys(data,["lease","code"]);const owned=lease(data.lease);
        if(data.code!=="UPSTREAM_UNAVAILABLE" && data.code!=="DISPATCH_REJECTED") throw new RpcFailure(400,"INVALID_REQUEST");
        await this.queue.fail(owned.tenantId,owned.jobId,owned.leaseToken,data.code);
        reply(response,200,{ok:true,data:null});return;
      }
    } else {
      if(path==="/gateway/open") {
        keys(data,["lease","capability"]);
        await this.open(response,lease(data.lease),text(data.capability,43));return;
      }
      if(path==="/gateway/check" || path==="/gateway/finish") {
        keys(data,path==="/gateway/check" ? ["tenantId","credentialId","claimToken"] : ["tenantId","credentialId","claimToken","success"]);
        const tenantId=text(data.tenantId),id=text(data.credentialId),claimToken=text(data.claimToken,43);
        if(path==="/gateway/check") {
          await this.capabilities.validateClaim(tenantId,id,claimToken);
          reply(response,200,{ok:true,data:{authorized:true}});return;
        }
        if(typeof data.success!=="boolean") throw new RpcFailure(400,"INVALID_REQUEST");
        const state=this.sessions.get(id);
        if(!state || state.claim.tenantId!==tenantId || !equalSecret(state.claim.claimToken,claimToken)) throw new RpcFailure(409,"AUTHORITY_LOST");
        reply(response,200,{ok:true,data:await this.finish(state,data.success)});return;
      }
    }
    throw new RpcFailure(403,"ROLE_FORBIDDEN");
  }

  private async open(response: ServerResponse,owned: ScanDispatchLease,value: string): Promise<void> {
    if(this.sessions.size>=2) throw new RpcFailure(503,"GATEWAY_CAPACITY");
    const claim=await this.capabilities.consume(owned,value);
    const state: OpenSession={claim,response,canceled:false};
    this.sessions.set(claim.credentialId,state);
    response.once("close",()=>{
      if(!state.finishing) {
        state.canceled=true;
        void this.finish(state,false).catch(()=>{this.ready=false;});
      }
    });
    state.resource=Promise.resolve().then(()=>this.provider.openReadSession(Number(claim.installationId),
      Number(claim.providerRepoId),claim.providerUserId,Date.parse(claim.expiresAt),async()=>{
        setImmediate(()=>{void this.finish(state,false).catch(()=>{this.ready=false;});});
      }));
    state.timer=setTimeout(()=>{
      state.canceled=true;
      void this.finish(state,false).catch(()=>{this.ready=false;});
    },Math.max(1,Date.parse(claim.expiresAt)-Date.now()));
    state.timer.unref?.();
    try {
      const resource=await state.resource;
      if(state.canceled || response.destroyed || state.finishing) {await this.finish(state,false);return;}
      response.writeHead(200,{"Content-Type":"application/x-ndjson","Cache-Control":"no-store"});
      const write=(chunk: Buffer)=>new Promise<void>((resolve,reject)=>{
        if(response.destroyed) {reject(new Error("GATEWAY_CLOSED"));return;}
        response.write(chunk,error=>error?reject(new Error("GATEWAY_CLOSED")):resolve());
      });
      const scope=Buffer.from(JSON.stringify({kind:"fetch-scope",claim})+"\n");
      try {await write(scope);} finally {scope.fill(0);}
      await resource.transfer(async frame=>{
        const chunk=Buffer.concat([frame,Buffer.from("\n")]);
        try {await write(chunk);} finally {chunk.fill(0);}
      });
      // Keep the response open: disconnect revokes, independent of the next RPC.
    } catch {
      await this.finish(state,false);
      if(!response.headersSent) reply(response,503,{ok:false,errorCode:"UPSTREAM_UNAVAILABLE"});
    }
  }

  private async finish(state: OpenSession,success: boolean): Promise<FetchGatewayCompletion> {
    if(state.finishing) return state.finishing;
    state.finishing=(async()=>{
      let revoked=false;
      try {const resource=await state.resource;if(resource) {await resource.revoke();revoked=true;}} catch { /* unknown is not success */ }
      try {
        return await this.capabilities.complete(state.claim.tenantId,state.claim.credentialId,state.claim.claimToken,
          {success:success&&!state.canceled,upstreamRevoked:revoked});
      } finally {
        if(state.timer) clearTimeout(state.timer);
        this.sessions.delete(state.claim.credentialId);
        if(!state.response.writableEnded && !state.response.destroyed) {
          if(state.response.headersSent) state.response.end();
          else reply(state.response,503,{ok:false,errorCode:"UPSTREAM_UNAVAILABLE"});
        }
      }
    })().catch(error=>{this.unhealthy();throw error;});
    return state.finishing;
  }

  async close(): Promise<void> {
    this.ready=false;
    const completion=await Promise.allSettled([...this.sessions.values()].map(state=>{state.canceled=true;return this.finish(state,false);}));
    for(const server of this.servers) {server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()));}
    for(const [path,inode] of this.socketInodes) {
      try {if((await lstat(path)).ino===inode) await unlink(path);} catch(error) {
        if((error as NodeJS.ErrnoException).code!=="ENOENT") throw new Error("SOCKET_CLEANUP_UNCONFIRMED");
      }
    }
    this.socketInodes.clear();
    if(this.finalizationFailed || completion.some(result=>result.status==="rejected")) throw new Error("BROKER_FINALIZATION_UNCONFIRMED");
  }
}
