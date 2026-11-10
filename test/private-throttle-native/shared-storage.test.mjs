import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import test from 'node:test';
import {createRuntimeThrottleStorage} from '../../apps/private-api/dist/common/security/redis-throttler.storage.js';

const require=createRequire(new URL('../../apps/private-api/package.json',import.meta.url));
require('reflect-metadata');
const {Controller,Get,Module}=require('@nestjs/common');
const {NestFactory,APP_GUARD}=require('@nestjs/core');
const {ThrottlerModule,ThrottlerGuard}=require('@nestjs/throttler');
const {createClient}=require('redis');
assert.equal(process.env.AEGISAI_DISPOSABLE_THROTTLE_REDIS,'1');
const url=new URL(process.env.REDIS_URL);
assert.equal(url.hostname,'throttle-redis');assert.equal(url.pathname,'/15');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

class ProbeController {
  shared(){return {ok:true};}
  isolated(){return {ok:true};}
}
Controller()(ProbeController);
for(const name of ['shared','isolated'])Get(name)(ProbeController.prototype,name,Object.getOwnPropertyDescriptor(ProbeController.prototype,name));

test('two actual HTTP apps share one atomic limit, block expiry and bounded outage behavior',{timeout:20000},async()=>{
  const apps=[],shutdown=[];
  const control=createClient({url:process.env.REDIS_URL});control.on('error',()=>undefined);
  try {
    await control.connect();
    for(let index=0;index<2;index++){
      const storage=await createRuntimeThrottleStorage({isTest:()=>false,get:key=>{assert.equal(key,'REDIS_URL');return process.env.REDIS_URL;}},
        {registerShutdownCallback:callback=>shutdown.push(callback)});
      class ProbeModule {}
      Module({imports:[ThrottlerModule.forRoot({throttlers:[{limit:3,ttl:1000,blockDuration:1000}],storage})],
        controllers:[ProbeController],providers:[{provide:APP_GUARD,useClass:ThrottlerGuard}]})(ProbeModule);
      const app=await NestFactory.create(ProbeModule,{logger:false});await app.listen(0,'127.0.0.1');apps.push(app);
    }
    async function request(index,path='shared'){
      const response=await fetch((await apps[index].getUrl())+'/'+path,{signal:AbortSignal.timeout(5000)});
      const body=await response.text();assert.ok(!body.includes(url.password)&&!body.includes('redis://'));
      return {status:response.status,retry:response.headers.get('retry-after')};
    }
    for(const index of [0,1,0])assert.equal((await request(index)).status,200);
    const blocked=await request(1);assert.equal(blocked.status,429);assert.equal(blocked.retry,'1');
    assert.equal((await request(1,'isolated')).status,200);
    await sleep(1100);
    const burst=await Promise.all(Array.from({length:10},(_,index)=>request(index%2)));
    assert.equal(burst.filter(value=>value.status===200).length,3);
    assert.equal(burst.filter(value=>value.status===429).length,7);
    await sleep(600);assert.equal((await request(0)).status,429);
    await sleep(550);assert.equal((await request(1)).status,200,'Blocked retries must not extend the block');
    const keys=await control.keys('aegisai:throttle:v1:*');assert.ok(keys.length<=4);
    for(const key of keys){assert.match(key,/^aegisai:throttle:v1:\{[a-f0-9]{64}\}:(hits|state)$/);assert.ok(await control.pTTL(key)>0);}
    await control.sendCommand(['CLIENT','PAUSE','2300','ALL']);
    const started=Date.now();assert.equal((await request(0)).status,503);assert.ok(Date.now()-started<2200);
    await sleep(1000);assert.equal((await request(1)).status,200,'Existing clients must recover after the store resumes');
    for(const callback of shutdown)await callback();shutdown.length=0;
    assert.equal((await request(0)).status,503,'A disconnected store cannot fall back to per-process counters');
    console.log(JSON.stringify({sharedHttpLimit:'passed',parallelAccepted:3,parallelRejected:7,
      actualExpiryVerified:true,blockNotExtended:true,routeIsolation:true,
      actualCommandTimeoutClosed:true,storeRecovery:true,disconnectedStoreClosed:true,productionDataUsed:false}));
  } finally {
    for(const app of apps)await app.close();
    for(const callback of shutdown)await callback();
    if(control.isOpen)await control.quit();
  }
});
