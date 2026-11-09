import { createHash } from "node:crypto";
import { DeleteObjectCommand, GetObjectCommand, HeadBucketCommand, HeadObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { ServiceUnavailableException } from "@nestjs/common";
import { MAX_EVIDENCE_TTL_MS } from "@aegisai/shared";

export interface EvidenceScope {tenantId:string;scanRequestId:string;id:string;expiresAt:Date;}
export interface EvidenceArtifact {objectKey:string;byteSize:number;}
export interface EvidenceStorage {
  put(scope:EvidenceScope,payload:unknown):Promise<EvidenceArtifact>;
  remove(objectKey:string):Promise<void>;
  read(scope:EvidenceScope,objectKey:string):Promise<Buffer>;
  healthy():Promise<boolean>;
}
export const EVIDENCE_MAX_BYTES=1024*1024;
function unavailable():never {throw new ServiceUnavailableException({errorCode:"EVIDENCE_STORAGE_UNAVAILABLE",message:"Encrypted evidence storage is unavailable."});}
export function evidenceObjectKey(scope:Pick<EvidenceScope,"tenantId"|"scanRequestId"|"id">):string {
  if([scope.tenantId,scope.scanRequestId,scope.id].some(value=>typeof value!=="string"||!/^[A-Za-z0-9_-]{1,128}$/.test(value))) return unavailable();
  return `evidence/${scope.tenantId}/${scope.scanRequestId}/${scope.id}.json`;
}

/** Native S3 envelope encryption with KMS-managed key and tenant-bound context. */
export class S3EvidenceStore implements EvidenceStorage {
  private readonly client:S3Client;
  private lastHealth=0;
  constructor(private readonly bucket:string,private readonly kmsKeyArn:string,region:string) {
    if(bucket!=="aegisai-private-024139495514-apne2" || region!=="ap-northeast-2" ||
      !/^arn:aws:kms:ap-northeast-2:024139495514:key\/[a-f0-9-]{36}$/.test(kmsKeyArn)) unavailable();
    this.client=new S3Client({region,maxAttempts:2});
  }
  static fromEnvironment():S3EvidenceStore {
    return new S3EvidenceStore(process.env.EVIDENCE_BUCKET??"",process.env.EVIDENCE_KMS_KEY_ARN??"",process.env.AWS_REGION??"");
  }
  async healthy():Promise<boolean> {
    if(Date.now()-this.lastHealth<60_000) return true;
    try {
      await this.client.send(new HeadBucketCommand({Bucket:this.bucket}),{abortSignal:AbortSignal.timeout(5000)});
      this.lastHealth=Date.now();return true;
    } catch {return false;}
  }
  async put(scope:EvidenceScope,payload:unknown):Promise<EvidenceArtifact> {
    const key=evidenceObjectKey(scope),bytes=Buffer.from(JSON.stringify(payload));
    if(bytes.length<1 || bytes.length>EVIDENCE_MAX_BYTES || !Number.isFinite(scope.expiresAt.getTime()) ||
      scope.expiresAt.getTime()<=Date.now() || scope.expiresAt.getTime()-Date.now()>MAX_EVIDENCE_TTL_MS+5000) unavailable();
    try {
      await this.client.send(new PutObjectCommand({Bucket:this.bucket,Key:key,Body:bytes,ContentLength:bytes.length,
        ContentType:"application/json",CacheControl:"private, no-store",IfNoneMatch:"*",
        ServerSideEncryption:"aws:kms",SSEKMSKeyId:this.kmsKeyArn,BucketKeyEnabled:false,
        SSEKMSEncryptionContext:Buffer.from(JSON.stringify({tenantId:scope.tenantId,scanRequestId:scope.scanRequestId,evidenceId:scope.id})).toString("base64"),
        ChecksumSHA256:createHash("sha256").update(bytes).digest("base64"),
        Metadata:{"expires-at":scope.expiresAt.toISOString(),"tenant-id":scope.tenantId,"scan-id":scope.scanRequestId,"evidence-id":scope.id,"classification":"SHORT_LIVED_EVIDENCE"}
      }),{abortSignal:AbortSignal.timeout(10_000)});
      return {objectKey:key,byteSize:bytes.length};
    } catch {this.lastHealth=0;return unavailable();}
    finally {bytes.fill(0);}
  }
  async remove(objectKey:string):Promise<void> {
    if(!/^evidence\/[A-Za-z0-9_-]{1,128}\/[A-Za-z0-9_-]{1,128}\/[A-Za-z0-9_-]{1,128}\.json$/.test(objectKey)) unavailable();
    try {await this.client.send(new DeleteObjectCommand({Bucket:this.bucket,Key:objectKey}),{abortSignal:AbortSignal.timeout(10_000)});}
    catch {this.lastHealth=0;unavailable();}
  }
  async read(scope:EvidenceScope,objectKey:string):Promise<Buffer> {
    if(objectKey!==evidenceObjectKey(scope)) unavailable();
    try {
      const response=await this.client.send(new GetObjectCommand({Bucket:this.bucket,Key:objectKey}),{abortSignal:AbortSignal.timeout(10_000)});
      if(response.ServerSideEncryption!=="aws:kms" || response.SSEKMSKeyId!==this.kmsKeyArn ||
        !response.Body || !response.ContentLength || response.ContentLength>EVIDENCE_MAX_BYTES || response.Metadata?.['tenant-id']!==scope.tenantId ||
        response.Metadata?.['scan-id']!==scope.scanRequestId || response.Metadata?.['evidence-id']!==scope.id || response.Metadata?.['expires-at']!==scope.expiresAt.toISOString()) unavailable();
      const chunks:Buffer[]=[];let size=0;
      const body=response.Body as unknown as AsyncIterable<Uint8Array>&{destroy?:(error?:Error)=>void};
      const timer=setTimeout(()=>body.destroy?.(new Error("EVIDENCE_READ_TIMEOUT")),10_000);
      try {for await(const value of body) {
        const chunk=Buffer.from(value);size+=chunk.length;
        if(size>EVIDENCE_MAX_BYTES) {body.destroy?.();unavailable();}
        chunks.push(chunk);
      }} finally {clearTimeout(timer);}
      const result=Buffer.concat(chunks);
      if(size!==response.ContentLength) unavailable();
      const data=JSON.parse(result.toString());
      if(data.tenantId!==scope.tenantId || data.scanRequestId!==scope.scanRequestId || data.evidenceId!==scope.id || data.redacted!==true) unavailable();
      return result;
    } catch {return unavailable();}
  }
  /** Bounded inventory for orphan cleanup; no content is downloaded. */
  async inventory(continuationToken?:string) {
    return this.client.send(new ListObjectsV2Command({Bucket:this.bucket,Prefix:"evidence/",MaxKeys:1000,ContinuationToken:continuationToken}),{abortSignal:AbortSignal.timeout(10_000)});
  }
  async describe(objectKey:string) {
    if(!/^evidence\/[A-Za-z0-9_-]{1,128}\/[A-Za-z0-9_-]{1,128}\/[A-Za-z0-9_-]{1,128}\.json$/.test(objectKey)) unavailable();
    return this.client.send(new HeadObjectCommand({Bucket:this.bucket,Key:objectKey}),{abortSignal:AbortSignal.timeout(10_000)});
  }
}
