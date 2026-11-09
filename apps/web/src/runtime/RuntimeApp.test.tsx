import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import RuntimeApp from "./RuntimeApp";

afterEach(()=>{vi.restoreAllMocks();sessionStorage.clear();window.history.replaceState({},'', '/');});
describe('Production runtime screen',()=>{
  it('submits only repository/branch with session CSRF and reads real-shaped results with AI disabled',async()=>{
    window.history.replaceState({},'', '/scan');
    let created=false;
    const csrf='t'.repeat(64);
    const scan={id:'scan_request_fixture',status:'COMPLETED',repositoryBindingId:'binding_fixture',repositoryName:'AigisAI/fixture',branch:'main',commitSha:'a'.repeat(40),createdAt:'2026-11-08T00:00:00Z',startedAt:null,completedAt:null};
    const fetch=vi.spyOn(globalThis,'fetch').mockImplementation(async(input,init)=>{
      const path=String(input);
      let value:unknown;
      if(path==='/api/auth/me') value={authenticated:true,csrfToken:csrf,user:{id:'actual-shaped-user',name:'Workspace owner',email:null}};
      else if(path==='/api/runtime/status') value={ready:true,busy:false,ai:'DISABLED',updatedAt:new Date().toISOString()};
      else if(path==='/api/runtime/repositories') value=[{id:'binding_fixture',fullName:'AigisAI/fixture',defaultBranch:'main'}];
      else if(path==='/api/runtime/scans'&&init?.method==='POST') {created=true;value={id:scan.id};}
      else if(path==='/api/runtime/scans') value=created?[scan]:[];
      else if(path==='/api/runtime/scans/'+scan.id) value={...scan,ai:'DISABLED',coverage:'LIMITED',runs:[],policy:null,
        findings:[{id:'finding_fixture',scanner:'TRIVY',ruleId:'CVE-2021-44228',title:'Dependency advisory CVE-2021-44228',severity:'CRITICAL',filePath:'pom.xml',lineStart:null,lineEnd:null,status:'OPEN'}]};
      else throw new Error('Unexpected fixture request');
      return new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}});
    });
    const queryClient=new QueryClient({defaultOptions:{queries:{retry:false},mutations:{retry:false}}});
    render(<QueryClientProvider client={queryClient}><RuntimeApp/></QueryClientProvider>);
    const button=await screen.findByRole('button',{name:'스캔 실행'});
    await waitFor(()=>expect(button).toBeEnabled());
    await userEvent.click(button);
    await screen.findByRole('heading',{name:'Dependency advisory CVE-2021-44228'});
    expect(screen.getByText(/줄 번호 없음/)).toBeInTheDocument();
    expect(screen.getAllByText('AI 꺼짐').length).toBeGreaterThan(0);
    const sent=fetch.mock.calls.find(([path,options])=>path==='/api/runtime/scans'&&options?.method==='POST');
    expect(JSON.parse(String(sent?.[1]?.body))).toEqual({repositoryBindingId:'binding_fixture'});
    expect(sent?.[1]?.headers).toEqual(expect.objectContaining({'X-CSRF-Token':csrf}));
    queryClient.clear();
  });
  it('ignores a stored demo session when the server says the user is signed out',async()=>{
    sessionStorage.setItem('aegisai.demo.enabled','1');sessionStorage.setItem('aegisai.demo.authenticated','1');
    const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({authenticated:false,csrfToken:'fixture',user:null}),{status:200}));
    const queryClient=new QueryClient({defaultOptions:{queries:{retry:false}}});
    render(<QueryClientProvider client={queryClient}><RuntimeApp/></QueryClientProvider>);
    expect(await screen.findByRole('link',{name:'GitHub로 로그인'})).toHaveAttribute('href','/api/auth/github');
    expect(fetch).toHaveBeenCalledTimes(1);
    queryClient.clear();
  });
});
