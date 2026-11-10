import { Injectable } from "@nestjs/common";
import { constants } from "node:fs";
import { lstat, open, readlink } from "node:fs/promises";
import type { RuntimeStatus } from "@aegisai/shared/private-runtime";
import { ConfigService } from "../config/config.service";

async function readOnlyCatalogMount(root:string):Promise<boolean> {
  const handle=await open('/proc/self/mountinfo',constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
    const raw=Buffer.alloc(65537);
    let used=0;
    while(used<raw.length) {
      const {bytesRead}=await handle.read(raw,used,raw.length-used,null);
      if(bytesRead===0) break;
      used+=bytesRead;
    }
    if(used>65536) return false;
    const matches=raw.subarray(0,used).toString().split('\n').map(line=>line.trim().split(/\s+/))
      .filter(fields=>fields.length>=10 && fields[4]===root);
    return matches.length===1 && matches[0][5].split(',').includes('ro') && !matches[0][5].split(',').includes('rw');
  } finally {await handle.close();}
}

@Injectable()
export class RuntimeCatalogService {
  constructor(private readonly config:ConfigService) {}

  async read(): Promise<RuntimeStatus> {
    try {
      const root="/run/aegisai-runtime";
      let path=root+"/current.json";
      let info=await lstat(path);
      if(info.isSymbolicLink()) {
        if(this.config.getOptional('RUNTIME_CATALOG_MODE')!=='projected' || info.uid!==0) throw new Error();
        const parent=await lstat(root);
        // Kubelet creates a 0777 volume root. Its actual per-mount read-only
        // flag, not the directory mode alone, prevents Pod-side replacement.
        if(!parent.isDirectory() || parent.isSymbolicLink() || parent.uid!==0 || !await readOnlyCatalogMount(root)) throw new Error();
        if(await readlink(path)!=='..data/current.json') throw new Error();
        const pointer=await lstat(root+'/..data');
        if(!pointer.isSymbolicLink() || pointer.uid!==0) throw new Error();
        const directory=await readlink(root+'/..data');
        if(!/^\.\.[0-9]{4}_(?:[0-9]{2}_){4}[0-9]{2}\.[0-9]{1,20}$/.test(directory)) throw new Error();
        const target=await lstat(root+'/'+directory);
        if(!target.isDirectory() || target.isSymbolicLink() || target.uid!==0 || (target.mode&0o022)!==0) throw new Error();
        path=root+'/'+directory+'/current.json';
        info=await lstat(path);
      }
      if(!info.isFile() || info.isSymbolicLink() || info.uid!==0 || info.size>4096 || (info.mode&0o022)!==0) throw new Error();
      const handle=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
      let text: string;
      try {
        const actual=await handle.stat();
        if(!actual.isFile() || actual.uid!==0 || actual.size>4096 || (actual.mode&0o022)!==0) throw new Error();
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
