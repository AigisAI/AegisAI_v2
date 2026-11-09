/** Explicit test fixture only. Production entrypoints always use S3/KMS. */
export class MemoryEvidenceStore {
  objects=new Map();
  async healthy(){return true;}
  async put(scope,payload){
    const objectKey=`evidence/${scope.tenantId}/${scope.scanRequestId}/${scope.id}.json`;
    const bytes=Buffer.from(JSON.stringify(payload));this.objects.set(objectKey,bytes);
    return {objectKey,byteSize:bytes.length};
  }
  async remove(key){this.objects.delete(key);}
  async read(_scope,key){return this.objects.get(key);}
  async inventory(){return {Contents:[]};}
  async describe(){throw new Error('No orphan fixture');}
}
