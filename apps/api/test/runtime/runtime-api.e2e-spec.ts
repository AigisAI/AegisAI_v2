import type { NestExpressApplication } from "@nestjs/platform-express";
import request from "supertest";
import { RuntimeApiService } from "../../src/runtime/runtime-api.service";
import { RuntimeCatalogService } from "../../src/runtime/runtime-catalog.service";
import { GithubAppClient } from "../../src/control-plane/github-app.client";
import { createTestApplication, loginTestAgent } from "../support/test-app";

describe('Real runtime HTTP entrypoint',()=>{
  let app:NestExpressApplication;
  beforeAll(async()=>{app=await createTestApplication();});
  afterEach(()=>jest.restoreAllMocks());
  afterAll(async()=>{await app.close();});
  it('requires a real session and CSRF before accepting new work',async()=>{
    await request(app.getHttpServer()).get('/api/runtime/scans').expect(401);
    await request(app.getHttpServer()).get('/api/runtime/repositories').expect(401);
    await request(app.getHttpServer()).post('/api/runtime/scans').send({repositoryBindingId:'binding'}).expect(403);
  });
  it('derives the principal from the session and rejects client SHA, tenant and scanner overrides',async()=>{
    const agent=request.agent(app.getHttpServer());
    const csrf=await loginTestAgent(agent,'tenant_runtime_fixture');
    const runtime=app.get(RuntimeApiService);
    const create=jest.spyOn(runtime,'create').mockResolvedValue({id:'synthetic'} as never);
    await agent.post('/api/runtime/scans').send({repositoryBindingId:'binding'}).expect(403);
    await agent.post('/api/runtime/scans').set('X-CSRF-Token',csrf).send({repositoryBindingId:'binding',tenantId:'foreign',commitSha:'a'.repeat(40),scannerSetVersion:'override'}).expect(400);
    expect(create).not.toHaveBeenCalled();
    await agent.post('/api/runtime/scans').set('X-CSRF-Token',csrf).send({repositoryBindingId:'binding',branch:'main'}).expect(201);
    expect(create).toHaveBeenCalledWith(expect.objectContaining({tenantId:'tenant_runtime_fixture',providerUserId:'42'}),'binding','main');
    const list=jest.spyOn(runtime,'list').mockResolvedValue([]);
    await agent.get('/api/runtime/scans?tenantId=foreign').expect('Cache-Control','no-store').expect(200,[]);
    expect(list).toHaveBeenCalledWith('tenant_runtime_fixture');
  });
  it('keeps creation closed when the real worker catalog is unavailable without consulting GitHub',async()=>{
    const agent=request.agent(app.getHttpServer());
    const csrf=await loginTestAgent(agent,'tenant_runtime_unavailable');
    jest.spyOn(app.get(RuntimeCatalogService),'read').mockResolvedValue({ready:false,busy:false,ai:'DISABLED',updatedAt:null});
    const provider=jest.spyOn(app.get(GithubAppClient),'resolveBranchCommit');
    await agent.post('/api/runtime/scans').set('X-CSRF-Token',csrf).send({repositoryBindingId:'binding'}).expect(503);
    expect(provider).not.toHaveBeenCalled();
  });
});
