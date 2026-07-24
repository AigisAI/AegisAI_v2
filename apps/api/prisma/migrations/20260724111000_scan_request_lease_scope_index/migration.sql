CREATE UNIQUE INDEX CONCURRENTLY "ScanRequest_id_tenantId_repositoryBindingId_key"
ON "ScanRequest"("id", "tenantId", "repositoryBindingId");
