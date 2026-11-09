import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { RepositoryBinding, RuntimeScanDetail, RuntimeScanSummary, RuntimeSessionResponse, RuntimeStatus } from "@aegisai/shared";
import "./runtime.css";

class RuntimeApiError extends Error {
  constructor(message:string,readonly status:number,readonly code?:string) {super(message);}
}
async function request<T>(path:string,options:{method?:string;body?:unknown;csrf?:string;signal?:AbortSignal}={}):Promise<T> {
  const response=await fetch('/api'+path,{method:options.method??'GET',credentials:'same-origin',cache:'no-store',signal:options.signal,
    headers:{...(options.body?{'Content-Type':'application/json'}:{}),...(options.csrf?{'X-CSRF-Token':options.csrf}:{})},
    ...(options.body?{body:JSON.stringify(options.body)}:{})});
  if(response.status===204) return null as T;
  const value=await response.json();
  if(!response.ok) throw new RuntimeApiError(typeof value.message==='string'?value.message:'요청을 처리하지 못했습니다.',response.status,value.errorCode);
  return value as T;
}
const labels:Record<string,string>={QUEUED:'대기 중',PLANNING:'준비 중',RUNNING:'분석 중',COMPLETED:'완료',FAILED:'실패',CANCELED:'취소됨',TIMED_OUT:'시간 초과',SKIPPED:'미실행'};
const active=(status:string)=>['QUEUED','PLANNING','RUNNING'].includes(status);
const time=(value:string)=>new Intl.DateTimeFormat('ko-KR',{dateStyle:'short',timeStyle:'short'}).format(new Date(value));
function Status({value}:{value:string}) {return <span className={'rt-status rt-status-'+value.toLowerCase()}>{labels[value]??value}</span>;}

function ScanResult({scan}:{scan:RuntimeScanDetail}) {
  const failures:Record<string,string>={UNSUPPORTED_SCAN_PROFILE:'현재 Java 파일이 있는 저장소만 지원합니다.',SOURCE_LIMIT_EXCEEDED:'저장소가 현재 분석 크기 제한을 초과했습니다.',SOURCE_ENTRY_UNSUPPORTED:'현재 지원하지 않는 저장소 항목이 포함되어 있습니다.',RUNTIME_SCOPE_UNSUPPORTED:'스캐너 구성이 변경됐습니다. 새 스캔을 요청해 주세요.'};
  return <section className="scan-section rt-result" aria-labelledby="rt-result-title">
    <div className="rt-section-heading"><div><p className="rt-eyebrow">분석 결과</p><h2 id="rt-result-title">{scan.repositoryName}</h2></div><Status value={scan.status}/></div>
    <p className="rt-commit">{scan.branch} <span aria-hidden="true">·</span> <code>{scan.commitSha.slice(0,12)}</code></p>
    {scan.failureReason?<div className="rt-error" role="status">{failures[scan.failureReason]??'이 저장소의 분석을 진행하지 못했습니다.'}</div>:null}
    <div className="rt-coverage" role="status">
      <strong>{scan.coverage==='PENDING'?'스캔을 기다리고 있습니다':scan.coverage==='UNAVAILABLE'?'분석이 완료되지 않았습니다':'제한된 범위의 분석 결과입니다'}</strong>
      <p>초기 Java 규칙과 선언된 의존성을 검사합니다. 전체 코드와 모든 간접 의존성의 안전성을 보장하지 않습니다.</p>
    </div>
    {scan.runs.length>0?<div className="rt-tool-runs">{scan.runs.map(run=><div key={run.scanner}><strong>{run.scanner}</strong><Status value={run.status}/><small>{run.scannerVersion}</small></div>)}</div>:null}
    <div className="rt-section-heading rt-findings-heading"><h3>발견된 항목 <span>{scan.findings.length}</span></h3><span className="rt-muted">AI 꺼짐</span></div>
    {scan.findings.length===0?<div className="rt-empty">{active(scan.status)?'분석이 진행되면 결과가 표시됩니다.':scan.status==='COMPLETED'?'검사 범위에서 발견된 항목이 없습니다.':'완료된 분석 결과가 없습니다.'}</div>:
      <div className="rt-findings">{scan.findings.map(finding=><article className="rt-finding" key={finding.id}>
        <span className={'rt-severity rt-severity-'+finding.severity.toLowerCase()}>{finding.severity}</span>
        <div><h4>{finding.title}</h4><p><code>{finding.filePath}</code>{finding.lineStart===null?' · 줄 번호 없음':` · ${finding.lineStart}행`}</p><small>{finding.scanner} · {finding.ruleId}</small></div>
      </article>)}</div>}
    {scan.policy?<p className="rt-policy">{scan.policy.action==='WARN'?'검토가 필요한 항목 또는 미완료 검사가 있습니다.':'결과와 분석 범위를 함께 확인해 주세요.'}</p>:null}
    {scan.evidence?<p className="rt-policy">{scan.evidence.available?<><a href={'/api/runtime/scans/'+encodeURIComponent(scan.id)+'/evidence'}>분석 근거 다운로드</a><span> · {time(scan.evidence.expiresAt)}까지 보관</span></>:'분석 근거의 보관 기간이 만료됐습니다.'}</p>:null}
  </section>;
}

function RuntimeLogin({failed=false}:{failed?:boolean}) {
  return <main className="login-page-v2">
    <header className="login-topbar-v2"><div className="login-topbar-inner-v2"><span className="login-wordmark-v2">AegisAI</span><span className="eyebrow">Private workspace</span></div></header>
    <div className="login-shell-v2"><section className="login-intro-v2"><h1>Authenticate Your Security</h1><p>GitHub 계정으로 비공개 보안 워크스페이스에 로그인하세요.</p></section>
      <section className="login-card-v2" aria-label="Secure provider access"><div className="login-card-accent" aria-hidden="true"/>
        {failed?<div className="login-alert-v2" role="alert"><strong>연결을 확인한 뒤 다시 로그인해 주세요.</strong></div>:null}
        <div className="login-provider-actions-v2"><a className="login-provider-button-v2" href="/api/auth/github" aria-label="GitHub로 로그인"><div className="login-provider-copy-v2"><span className="login-provider-glyph-v2" aria-hidden="true">GH</span><span>Continue with GitHub</span></div><span className="login-provider-arrow-v2" aria-hidden="true">→</span><p>저장소 접근 권한은 별도의 GitHub App으로 관리합니다.</p></a></div>
        <div className="login-status-block-v2"><div className="login-trust-grid-v2"><div className="login-trust-chip-v2 login-trust-chip-strong-v2">Tailscale Private Access</div><div className="login-trust-chip-v2">Encrypted Sessions</div></div></div>
      </section></div>
  </main>;
}

export default function RuntimeApp() {
  const queryClient=useQueryClient();
  const [repositoryId,setRepositoryId]=useState('');
  const [branch,setBranch]=useState('');
  const [selectedScan,setSelectedScan]=useState('');
  const session=useQuery({queryKey:['runtime','session'],queryFn:({signal})=>request<RuntimeSessionResponse>('/auth/me',{signal}),retry:false,staleTime:60_000});
  const authenticated=session.data?.authenticated===true;
  const status=useQuery({queryKey:['runtime','status'],queryFn:({signal})=>request<RuntimeStatus>('/runtime/status',{signal}),enabled:authenticated,retry:false,refetchInterval:10_000});
  const repositories=useQuery({queryKey:['runtime','repositories'],queryFn:({signal})=>request<RepositoryBinding[]>('/runtime/repositories',{signal}),enabled:authenticated,retry:false,staleTime:60_000});
  const scans=useQuery({queryKey:['runtime','scans'],queryFn:({signal})=>request<RuntimeScanSummary[]>('/runtime/scans',{signal}),enabled:authenticated,retry:false,
    refetchInterval:query=>query.state.data?.some(scan=>active(scan.status))?5000:15000});
  const scanId=selectedScan||scans.data?.[0]?.id||'';
  const detail=useQuery({queryKey:['runtime','detail',scanId],queryFn:({signal})=>request<RuntimeScanDetail>('/runtime/scans/'+encodeURIComponent(scanId),{signal}),enabled:authenticated&&!!scanId,retry:false,
    refetchInterval:query=>query.state.data&&active(query.state.data.status)?3000:false});
  const requestedRepository=new URLSearchParams(window.location.search).get('repo');
  const selectedRepository=repositoryId||(repositories.data?.some(repo=>repo.id===requestedRepository)?requestedRepository:'')||repositories.data?.[0]?.id||'';
  const currentRepository=repositories.data?.find(repository=>repository.id===selectedRepository);
  const create=useMutation({mutationFn:()=>request<{id:string}>('/runtime/scans',{method:'POST',csrf:session.data?.csrfToken,
      body:{repositoryBindingId:selectedRepository,...(branch.trim()?{branch:branch.trim()}:{})}}),
    onSuccess:async scan=>{setSelectedScan(scan.id);await queryClient.invalidateQueries({queryKey:['runtime','scans']});}});
  const logout=useMutation({mutationFn:()=>request('/auth/logout',{method:'POST',body:{},csrf:session.data?.csrfToken}),
    onSuccess:async()=>{await queryClient.cancelQueries();queryClient.clear();window.location.assign('/');}});
  const error=session.error??status.error??repositories.error??scans.error??detail.error??create.error??logout.error;
  const expired=error instanceof RuntimeApiError&&(error.status===401||error.code==='DEPLOYMENT_ACCOUNT_NOT_ALLOWED');
  const view=window.location.pathname==='/repos'?'repos':window.location.pathname==='/scan'?'scan':'dashboard';
  const prefix=view==='repos'?'repos':view==='scan'?'scan':'dashboard';
  const headings={dashboard:['Operational overview','Read the latest security posture before you open the next report'],repos:['Connection hub','Begin the Archive'],scan:['Scan orchestration','Orchestrate the next review']} as const;
  if(session.isPending) return <main className="centered-state" role="status">로그인 상태를 확인하고 있습니다…</main>;
  if(!authenticated||expired) return <RuntimeLogin failed={!!session.error}/>;

  return <div className="app-shell">
    <aside className="app-sidebar"><div className="brand-block"><p className="eyebrow">AegisAI</p><h1 className="brand-title">Private Workspace</h1></div>
      <nav aria-label="Primary" className="nav-list">{[['dashboard','Dashboard'],['repos','Repositories'],['scan','Scan']].map(([path,label])=><a key={path} href={'/'+path} className={'nav-link'+(view===path?' is-active':'')} aria-current={view===path?'page':undefined}>{label}</a>)}</nav>
    </aside>
    <div className="app-content"><header className="app-header"><div><p className="eyebrow">Signed in</p><strong>{session.data?.user?.name??'Workspace owner'}</strong></div><button className="ghost-button" onClick={()=>logout.mutate()} disabled={logout.isPending} type="button">Logout</button></header>
      <main className="page-frame"><section className={prefix+'-page'}>
        <header className={prefix+'-hero'}><div className={prefix+'-hero-copy'}><p className="eyebrow">{headings[view][0]}</p><h2>{headings[view][1]}</h2><div className={prefix+'-hero-accent'}><p>{view==='repos'?'GitHub App에 연결된 저장소를 확인하고 읽기 전용 Java 분석을 시작하세요.':view==='scan'?'브랜치를 선택하고 스캔 진행 상태와 분석 결과를 확인하세요.':'연결된 저장소와 최근 보안 분석 결과를 한 곳에서 확인하세요.'}</p></div></div><div className={prefix+'-hero-panel'}><span className={prefix+'-hero-panel-kicker'}>{status.data?.ready?(status.data.busy?'분석 진행 중':'스캐너 준비됨'):'스캐너 일시 대기'} · AI 꺼짐</span></div></header>
        {error?<div className="scan-inline-alert" role="alert">{error instanceof Error?error.message:'요청을 처리하지 못했습니다.'}</div>:null}
        {view==='repos'?<section className="repos-section" aria-label="Connected repositories"><div className="repos-section-heading"><p className="eyebrow">Connected repositories</p><h3>Protected sources already in scope</h3></div>
          {repositories.isPending?<p role="status">저장소를 불러오고 있습니다…</p>:repositories.data?.length===0?<p>연결된 저장소가 없습니다.</p>:<div className="repos-list">{repositories.data?.map(repository=><article className="repos-record" key={repository.id}><div className="repos-record-body"><div className="repos-record-header"><span className="repos-provider-badge">GitHub</span><span className="repos-privacy-badge">{repository.isPrivate?'Private':'Public'}</span></div><div className="repos-record-copy"><h4>{repository.fullName}</h4><p>Default branch: {repository.defaultBranch}</p></div></div><a className="repos-secondary-action" href={'/scan?repo='+encodeURIComponent(repository.id)}>Scan repository →</a></article>)}</div>}
        </section>:null}
        {view==='dashboard'?<section className="dashboard-section" aria-label="Summary snapshot"><div className="dashboard-section-heading"><p className="eyebrow">Summary snapshot</p><h3>Recent signal across connected repositories</h3></div><div className="dashboard-metric-grid">
          <article className="dashboard-metric-tile"><span>Connected repos</span><strong>{repositories.isPending?'—':repositories.data?.length??'—'}</strong><p>연결된 저장소</p></article>
          <article className="dashboard-metric-tile"><span>Recent scans</span><strong>{scans.isPending?'—':scans.data?.length??'—'}</strong><p>최근 스캔 기록 · 최대 50건</p></article>
          <article className="dashboard-metric-tile"><span>Completed reviews</span><strong>{scans.isPending?'—':scans.data?.filter(scan=>scan.status==='COMPLETED').length??'—'}</strong><p>최근 기록 중 완료된 분석</p></article>
          <article className="dashboard-metric-tile"><span>AI advisory</span><strong>Off</strong><p>AI 없이 분석과 결과 조회 가능</p></article>
        </div><a className="dashboard-secondary-link" href="/scan">새 스캔 시작 →</a></section>:null}
        {view==='scan'?<section className="scan-section scan-request-card" aria-labelledby="rt-create-title"><div className="scan-section-heading"><p className="eyebrow">Request a scan</p><h3 id="rt-create-title">Select the source before analysis starts</h3></div>
          <form onSubmit={event=>{event.preventDefault();create.mutate();}}><div className="scan-form-grid"><label className="scan-field"><span>Repository</span><select value={selectedRepository} onChange={event=>{setRepositoryId(event.target.value);setBranch('');}} disabled={repositories.isPending||create.isPending} required><option value="" disabled>저장소 선택</option>{repositories.data?.map(repository=><option value={repository.id} key={repository.id}>{repository.fullName}</option>)}</select></label>
            <label className="scan-field"><span>Branch</span><input value={branch} onChange={event=>setBranch(event.target.value)} maxLength={255} placeholder={currentRepository?.defaultBranch??'기본 브랜치'} disabled={create.isPending}/></label></div>
            <div className="scan-form-footer"><div className="scan-form-hint"><strong>Read only. Queue first.</strong><p>브랜치를 비워 두면 기본 브랜치를 분석합니다.</p></div><button className="rt-button" type="submit" disabled={!status.data?.ready||!selectedRepository||create.isPending}>{create.isPending?'스캔 요청 중…':status.data?.busy?'대기열에 추가':'스캔 실행'}</button></div>
          </form>{repositories.data?.length===0?<p>연결된 저장소가 없습니다.</p>:null}</section>:null}
        {view!=='repos'?<div className="rt-content-grid"><section className="dashboard-section rt-history" aria-labelledby="rt-history-title"><div className="dashboard-section-heading"><p className="eyebrow">Recent reviews</p><h3 id="rt-history-title">최근 스캔</h3></div>
          {scans.isPending?<p role="status">스캔을 불러오고 있습니다…</p>:scans.data?.length===0?<p className="dashboard-state-copy">아직 실행한 스캔이 없습니다.</p>:<div className="dashboard-scan-list">{scans.data?.map(scan=><button type="button" key={scan.id} className={'dashboard-scan-card'+(scan.id===scanId?' is-selected':'')} onClick={()=>setSelectedScan(scan.id)} aria-pressed={scan.id===scanId}><div className="dashboard-scan-header"><strong>{scan.repositoryName.split('/').slice(1).join('/')}</strong><Status value={scan.status}/></div><div className="dashboard-scan-meta"><span>{scan.branch}</span><code>{scan.commitSha.slice(0,8)}</code></div><small>{time(scan.createdAt)}</small></button>)}</div>}
        </section>{detail.data?<ScanResult scan={detail.data}/>:<section className="scan-section rt-empty" role="status">{detail.isPending&&scanId?'분석 결과를 불러오고 있습니다…':'스캔을 선택하면 결과가 표시됩니다.'}</section>}</div>:null}
      </section></main></div>
  </div>;
}
