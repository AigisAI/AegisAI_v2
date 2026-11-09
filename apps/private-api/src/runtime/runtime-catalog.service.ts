import { Injectable } from "@nestjs/common";
import { lstat, open } from "node:fs/promises";
import type { RuntimeStatus } from "@aegisai/shared/private-runtime";

@Injectable()
export class RuntimeCatalogService {
  async read(): Promise<RuntimeStatus> {
    try {
      const path="/run/aegisai-runtime/current.json";
      const info=await lstat(path);
      if(!info.isFile() || info.isSymbolicLink() || info.uid!==0 || info.size>4096 || (info.mode&0o022)!==0) throw new Error();
      const handle=await open(path,"r");
      let text: string;
      try {
        const raw=Buffer.alloc(4097);
        const {bytesRead}=await handle.read(raw,0,raw.length,0);
        if(bytesRead>4096) throw new Error();
        text=raw.subarray(0,bytesRead).toString();
      } finally {await handle.close();}
      const value=JSON.parse(text);
      const age=Date.now()-Date.parse(value.updatedAt);
      if(typeof value.ready!=="boolean" || typeof value.busy!=="boolean" || value.ai!=="DISABLED" ||
        !Number.isFinite(age) || age < -5000 || age>60000) throw new Error();
      if(value.ready && (!/^java-v1:[a-f0-9]{16}:[a-f0-9]{64}$/.test(value.scannerSetVersion) || value.policyVersion!=="private-java-v1")) throw new Error();
      return {ready:value.ready,busy:value.busy,ai:"DISABLED",updatedAt:value.updatedAt,
        ...(value.ready?{scannerSetVersion:value.scannerSetVersion,policyVersion:value.policyVersion}:{})};
    } catch {return {ready:false,busy:false,ai:"DISABLED",updatedAt:null};}
  }
}
