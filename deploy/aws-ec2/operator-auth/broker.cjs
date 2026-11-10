// Local Windows operator only. No credentials, browser cookies or AWS keys in Git.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8').replace(/^\uFEFF/,''));
const {chromium}=require(path.join(__dirname,'node_modules/playwright-core'));
const origin='https://aegisai-aws.tailaca7d2.ts.net';
const sshArgs=['-i',config.sshKey,'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','ubuntu@100.64.144.15'];
const statusFile=path.join(__dirname,'status.json');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let status={lastAuthorizationAt:Date.now(),failures:0};
try{status={...status,...JSON.parse(fs.readFileSync(statusFile,'utf8'))};}catch{}
function save(state){status={...status,state,lastCheckedAt:new Date().toISOString()};fs.writeFileSync(statusFile,JSON.stringify(status,null,2));}
function ssh(code){return cp.execFileSync(config.ssh,[...sshArgs,'sudo python3 -'],{input:code,encoding:'utf8',timeout:60000,windowsHide:true,stdio:['pipe','pipe','pipe']}).trim();}
function check(){return JSON.parse(ssh("import subprocess\np=subprocess.run(['python3','/opt/aegisai/operator/operator-auth-check.py'],capture_output=True,text=True,timeout=40)\nassert p.returncode==0\nprint(p.stdout)"));}
function credentials(){
  const raw=cp.execFileSync(config.powershell,['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(__dirname,'decrypt.ps1'),'-Path',config.encryptedCredential],{encoding:'utf8',windowsHide:true,stdio:['ignore','pipe','pipe']});
  const value=JSON.parse(raw);
  if(value.accountId!=='024139495514'||value.username!=='goodtu02'||typeof value.password!=='string')throw Error('INVALID_LOCAL_IDENTITY');
  return value;
}
async function authorize(){
  let context,unit;
  try{
    context=await chromium.launchPersistentContext(config.browserProfile,{channel:'chrome',headless:true,acceptDownloads:false});
    const page=await context.newPage();
    await page.goto('https://024139495514.signin.aws.amazon.com/console',{waitUntil:'domcontentloaded'});
    await Promise.race([page.locator('input#password').waitFor({state:'visible',timeout:30000}),page.waitForURL('https://*.console.aws.amazon.com/**',{timeout:30000})]);
    if(await page.locator('input#password').isVisible()){
      const value=credentials();
      await page.locator('input#account').fill(value.accountId);await page.locator('input#username').fill(value.username);
      await page.locator('input#password').fill(value.password);value.password='';
      await page.getByRole('button',{name:'Sign in',exact:true}).click();
      await page.waitForURL('https://*.console.aws.amazon.com/**',{timeout:45000});
    }
    await page.getByText('goodtu02',{exact:false}).first().waitFor({timeout:30000});
    if(!(await page.locator('body').innerText()).includes('goodtu02'))throw Error('UNEXPECTED_CONSOLE_IDENTITY');
    unit='aegisai-aws-auto-'+Date.now();
    const remote=JSON.parse(ssh(`import subprocess,pathlib,time,json\np=pathlib.Path('/opt/aegisai/operator/aws-login-session.json')\nassert subprocess.run(['sh','-c','ss -lnt sport = :8766 | tail -n +2 | grep -q .'],capture_output=True).returncode!=0\nstarted=time.time()\nsubprocess.run(['systemd-run','--quiet','--unit=${unit}','--property=RuntimeMaxSec=910','--property=MemoryMax=64M','--property=CPUQuota=15%','/usr/bin/python3','/opt/aegisai/operator/aws-remote-login.py'],check=True)\nsubprocess.run(['tailscale','serve','--bg','--https=443','--set-path=/ops/aws-login','http://127.0.0.1:8766'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)\nfor n in range(20):\n if p.exists() and p.stat().st_mtime>=started:\n  print(p.read_text());break\n time.sleep(0.5)\nelse:raise RuntimeError('AUTH_SESSION_NOT_READY')`));
    if(!new RegExp('^'+origin.replaceAll('.','\\.')+'/ops/aws-login/[A-Za-z0-9_-]{43}$').test(remote.url))throw Error('INVALID_HANDOFF_ORIGIN');
    const handoff=await context.newPage();await handoff.goto(remote.url);
    const link=handoff.getByRole('link',{name:'1. AWS 공식 로그인 열기'});
    for(let n=0;n<30 && !(await link.count());n++){await sleep(1000);await handoff.reload();}
    await link.waitFor({timeout:30000});
    const href=new URL(await link.getAttribute('href'));
    const allowed=new Set(['ap-northeast-2.signin.amazonaws.com','signin.ap-northeast-2.amazonaws.com','ap-northeast-2.signin.aws.amazon.com']);
    if(href.protocol!=='https:'||!allowed.has(href.hostname)||href.username||href.password)throw Error('INVALID_OFFICIAL_AUTH_ORIGIN');
    const popup=context.waitForEvent('page');await link.click();const auth=await popup;await auth.waitForLoadState('domcontentloaded');
    const active=auth.getByText('goodtu02',{exact:true});await active.waitFor({timeout:30000});
    if(!(await auth.locator('body').innerText()).replaceAll('-','').replaceAll(' ','').includes('024139495514'))throw Error('WRONG_ACTIVE_ACCOUNT');
    await active.click();await auth.getByText('Show the full verification code',{exact:true}).waitFor({timeout:30000});
    await auth.getByText('Show the full verification code',{exact:true}).click();
    let code=(await auth.locator('code').innerText()).trim();if(!/^[A-Za-z0-9_+\/=.-]{16,4096}$/.test(code))throw Error('INVALID_CODE_FORMAT');
    const nonce=remote.url.split('/').at(-1);
    const response=await fetch(remote.url,{method:'POST',headers:{Origin:origin,Cookie:'aws_ops='+nonce,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:nonce,code}).toString(),signal:AbortSignal.timeout(15000)});code='';
    if(response.status!==200)throw Error('AUTH_HANDOFF_REJECTED');
    for(let n=0;n<12;n++){await sleep(1000);if(check().state==='connected'){status.lastAuthorizationAt=Date.now();status.failures=0;save('connected');return;}}
    throw Error('AUTH_IDENTITY_NOT_VERIFIED');
  }finally{
    if(context)await context.close().catch(()=>{});
    if(unit){try{ssh(`import subprocess\nsubprocess.run(['systemctl','stop','${unit}'],check=False)\nsubprocess.run(['tailscale','serve','--bg','--https=443','--set-path=/ops/aws-login','off'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)`);}catch{}}
  }
}
async function tick(force=false){
  const current=check();
  if(current.state==='wrong-principal')throw Error('WRONG_OPERATOR');
  if(force||current.state==='needs-login'||Date.now()-status.lastAuthorizationAt>=6*3600000)await authorize();
  else save(current.state);
}
(async()=>{
  if(process.argv.includes('--renew-once')){await tick(true);console.log('OPERATOR_RECONNECT_VERIFIED');return;}
  if(process.argv.includes('--once')){await tick();console.log('OPERATOR_MAINTENANCE_VERIFIED');return;}
  while(true){
    try{if(status.failures<2)await tick();}
    catch{status.failures++;save('requires-attention');}
    await sleep(status.state==='requires-attention'?3600000:300000);
  }
})().catch(()=>{save('requires-attention');console.error('OPERATOR_AUTHENTICATION_NOT_READY');process.exitCode=1;});
