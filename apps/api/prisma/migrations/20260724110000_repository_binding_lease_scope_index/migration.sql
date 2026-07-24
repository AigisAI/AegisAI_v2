CREATE UNIQUE INDEX CONCURRENTLY "RepositoryBinding_id_tenantId_key"
ON "RepositoryBinding"("id", "tenantId");
