'use client';

import { useEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowLeft, ArrowRight, ArrowUpRight, Check, CheckCheck, CircleAlert, CodeXml, Heart, LockKeyhole, Package, RotateCcw, Share2, ShieldCheck, ShoppingBag, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import './direct.css';

const phases = ['출시 전', '위험 발견', '수정 방향', '체험 완료'];
const titles = [<>잘 돌아가면,<br /><em>안전한 걸까요?</em></>, <>내 주문만<br /><em>보여야 하는데.</em></>, <>명령은 고정.<br /><em>입력은 따로.</em></>, <>위험을 찾고,<br /><em>다음 행동까지.</em></>];
const summaries = ['작은 쇼핑몰의 출시를 앞두고 있습니다.\n30초만 투자해 숨은 위험을 찾아보세요.', '입력값이 조회 명령에 섞이면\n예상 밖의 정보가 보일 수 있습니다.', '어떻게 바꾸면 될까요?\n수정 전과 제안된 방향을 비교해 보세요.', '보안 경고를 이해하고 고치는 과정.\nAegisAI가 연결하려는 경험입니다.'];

function Receipt({ other = false }: { other?: boolean }) {
  return <div className={`lab-receipt${other ? ' other-order' : ''}`}><div className="lab-package"><Package size={21} /></div><div><strong>{other ? '다른 고객의 주문' : '내 주문'}</strong><span>{other ? '접근하면 안 되는 정보' : '에센셜 티셔츠 · 1개'}</span></div><span className="lab-order-id">{other ? 'ORD-1025' : 'ORD-1024'}</span></div>;
}

export default function DirectExperience({ interestEndpoint = '/api/interest' }: { interestEndpoint?: string }) {
  const [phase, setPhase] = useState(0);
  const [showCode, setShowCode] = useState(false);
  const [interest, setInterest] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [shareMessage, setShareMessage] = useState('');
  const [shareUrl, setShareUrl] = useState('');
  const [manualShare, setManualShare] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const firstRender = useRef(true);
  const saving = useRef(false);
  useEffect(() => {
    if (firstRender.current) { firstRender.current = false; return; }
    heading.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'instant' });
  }, [phase]);
  function move(next: number) { setPhase(next); setShowCode(false); setShareMessage(''); setManualShare(false); }
  async function expressInterest() {
    if (saving.current || interest === 'saved') return;
    saving.current = true; setInterest('saving');
    try {
      const response = await fetch(interestEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"interested":true}', signal: AbortSignal.timeout(12000) });
      const result: unknown = await response.json();
      if (!response.ok || !result || typeof result !== 'object' || !('ok' in result) || result.ok !== true) throw new Error('Interest not saved');
      setInterest('saved');
    } catch { setInterest('error'); }
    finally { saving.current = false; }
  }
  async function share() {
    const url = new URL('/expo2', window.location.origin).href;
    setShareUrl(url); setShareMessage(''); setManualShare(false);
    if (navigator.share) {
      try { await navigator.share({ title: 'AegisAI · 출시 전 30초', text: '잘 돌아가면 안전한 걸까요? 쇼핑몰의 숨은 위험을 확인해 보세요.', url }); return; }
      catch (error) { if (error instanceof Error && error.name === 'AbortError') return; }
    }
    try { await navigator.clipboard.writeText(url); setShareMessage('체험 링크를 복사했어요.'); }
    catch { setManualShare(true); setShareMessage('아래 주소를 길게 눌러 복사하세요.'); }
  }

  return <div className="lab-page">
    <a className="lab-skip" href="#lab-main">체험으로 바로가기</a>
    <div className="lab-container">
      <header className="lab-header"><Button variant="ghost" className="lab-brand" onClick={() => move(0)} aria-label="AegisAI 처음으로"><ShieldCheck size={25} /><span>aegis<span>ai</span></span></Button><span className="lab-edition">EXPO / 2026</span></header>
      <main id="lab-main" className="lab-main">
        <div className="lab-story"><div className="lab-kicker"><span />RELEASE CHECK <i>001</i></div><h1 ref={heading} tabIndex={-1}>{titles[phase]}</h1><p className="lab-summary">{summaries[phase]}</p><div className="lab-mission-meta"><span>30<span>초</span></span><div>회원가입 없이<br />직접 확인하는 보안</div></div><p className="lab-story-foot">작동하는 코드와<br />안전한 코드 사이.</p></div>
        <div className="lab-workspace">
          <div className="lab-stepbar" aria-label={`4단계 중 ${phase + 1}단계: ${phases[phase]}`}><span><b>0{phase + 1}</b> / 04</span><strong>{phases[phase]}</strong><div aria-hidden="true">{phases.map((name, index) => <i key={name} className={index <= phase ? 'lit' : ''} />)}</div></div>
          <section className={`lab-scene scene-${phase}`} aria-label={`${phases[phase]} 체험`} key={phase}>
            {phase === 0 && <>
              <div className="lab-shop"><div className="lab-shop-header"><span><ShoppingBag size={17} />MONO STORE</span><span>SAMPLE</span></div><div className="lab-shop-body"><p className="lab-shop-label">MY ORDERS</p><h2>주문이 잘 들어갔네요.</h2><div className="lab-lookup"><span>주문번호</span><code>ORD-1024</code><Check size={16} /></div><Receipt /><div className="lab-normal"><span /><span>주문 조회 정상 작동</span><CheckCheck size={16} /></div></div></div>
              <div className="lab-prompt"><span className="lab-prompt-mark">?</span><p>그런데, 이 화면만 보고<br /><strong>출시를 결정해도 될까요?</strong></p></div>
              <Button className="lab-primary" onClick={() => move(1)}><span>숨은 위험 확인하기</span><ArrowRight size={21} /></Button>
            </>}
            {phase === 1 && <>
              <div className="lab-alert-heading"><span>01 ISSUE FOUND</span><span>샘플 결과</span></div>
              <div className="lab-shop lab-exposed"><div className="lab-shop-header"><span><ShoppingBag size={17} />MONO STORE</span><CircleAlert size={18} /></div><div className="lab-shop-body"><Receipt /><div className="lab-boundary"><span>여기까지가 내 정보</span><span /></div><Receipt other /><div className="lab-exposure-caption"><CircleAlert size={15} />보여서는 안 되는 주문까지</div></div></div>
              <div className="lab-explanation"><span className="lab-tech-label">SQL INJECTION · CWE-89</span><h2>입력값이 명령을 바꾸는 틈.</h2><p>주문번호를 조회 명령에 그대로 붙이면, 입력에 따라 조회 범위가 달라질 위험이 생깁니다.</p></div>
              <Button className="lab-primary" onClick={() => move(2)}><span>수정 방향 살펴보기</span><ArrowRight size={21} /></Button>
            </>}
            {phase === 2 && <>
              <div className="lab-fix-label"><Sparkles size={16} />AI 수정 제안 예시<span>자동 적용 없음</span></div>
              <Tabs defaultValue="after" className="lab-tabs"><TabsList className="lab-tabs-list" aria-label="수정 전후 비교"><TabsTrigger value="before">수정 전</TabsTrigger><TabsTrigger value="after">수정 예시</TabsTrigger></TabsList><TabsContent value="before"><div className="lab-query before-query"><div className="lab-query-caption"><CircleAlert size={20} /><span>하나의 명령으로 섞여요</span></div><div className="lab-query-block"><span>조회 명령</span><b>+</b><em>입력값</em></div><p>입력에 따라 명령의 의미가 달라질 수 있습니다.</p></div></TabsContent><TabsContent value="after"><div className="lab-query after-query"><div className="lab-query-caption"><LockKeyhole size={20} /><span>정해진 명령에 값만 전달해요</span></div><div className="lab-query-block"><span>고정된 명령</span><ArrowDown size={17} /><em>별도의 입력값</em></div><p>명령의 구조를 유지하는 파라미터 바인딩 예시입니다.</p></div></TabsContent></Tabs>
              <Button className="lab-code-toggle" variant="ghost" onClick={() => setShowCode(!showCode)} aria-expanded={showCode} aria-controls="lab-code"><CodeXml size={17} /><span>{showCode ? '코드 접기' : '코드로 차이 확인하기'}</span><span>{showCode ? '−' : '+'}</span></Button>
              {showCode && <div className="lab-code" id="lab-code"><span>BEFORE</span><pre>{'"SELECT * FROM orders WHERE id = "\n  + orderId'}</pre><span>AFTER · 수정 예시</span><pre>{'jdbcTemplate.queryForObject(\n  "SELECT * FROM orders WHERE id = ?",\n  orderMapper, orderId\n);'}</pre><p>사용자 권한 검사는 별도로 필요합니다.</p></div>}
              <div className="lab-human-note"><ShieldCheck size={19} /><p>AI는 수정 방향을 돕습니다.<br /><strong>최종 검토와 재점검은 개발자의 몫.</strong></p></div>
              <Button className="lab-primary" onClick={() => move(3)}><span>체험 마치기</span><ArrowRight size={21} /></Button>
            </>}
            {phase === 3 && <>
              <div className="lab-complete-header"><div><CheckCheck size={29} /></div><span>REVIEW COMPLETE<br /><strong>수정 방향 확인 완료</strong></span></div>
              <div className="lab-complete-copy"><h2>경고만 남기지 않도록.</h2><p>무엇이 위험한지, 왜 고쳐야 하는지,<br />어디서 시작할지 한 흐름으로 확인해요.</p></div>
              <ol className="lab-recap"><li><span>01</span><strong>발견</strong><p>분석 결과와 근거 확인</p></li><li><span>02</span><strong>이해</strong><p>원인과 수정 방향 검토</p></li><li><span>03</span><strong>조치</strong><p>개발자가 수정 후 재점검</p></li></ol>
              <div className="lab-interest"><h3>이런 도구, 우리 팀에도 필요하다면.</h3><Button className={`lab-primary${interest === 'saved' ? ' lab-saved' : ''}`} disabled={interest === 'saving' || interest === 'saved'} onClick={expressInterest}><span>{interest === 'saved' ? '관심을 남겼어요' : interest === 'saving' ? '저장하는 중…' : interest === 'error' ? '다시 관심 남기기' : '관심 있어요'}</span>{interest === 'saved' ? <Check size={20} /> : <Heart size={20} />}</Button><p>연락처 없이 관심 건수만 저장해요.<br />신청·구독으로 연결되지는 않습니다.</p><output className="lab-message">{interest === 'error' ? '저장하지 못했어요. 연결을 확인한 뒤 다시 눌러주세요.' : interest === 'saved' ? '감사합니다. 전시 부스에서 더 이야기 나눠요.' : ''}</output></div>
              <div className="lab-end-actions"><Button variant="ghost" onClick={share}><Share2 size={17} />체험 공유</Button><a href="https://aegisai.tailaca7d2.ts.net/" target="_blank" rel="noopener noreferrer">전체 데모<ArrowUpRight size={18} /></a></div><output className="lab-message">{shareMessage}</output>{manualShare && <input className="lab-share-url" aria-label="공유할 주소" readOnly value={shareUrl} onFocus={(event) => event.target.select()} />}
            </>}
          </section>
          <div className="lab-navigation">{phase > 0 ? <><Button variant="ghost" onClick={() => move(phase - 1)}><ArrowLeft size={15} />이전</Button><Button variant="ghost" onClick={() => move(0)}><RotateCcw size={15} />처음부터</Button></> : <span><LockKeyhole size={14} />개인정보 입력 없이 바로 체험</span>}</div>
          <p className="lab-sample-note">샘플 데이터로 구성한 프로토타입입니다.<br />실제 공격·분석·AI 추론은 실행하지 않습니다.</p>
        </div>
      </main>
      <footer className="lab-footer"><span>AEGISAI</span><span>BUILD WITH CONFIDENCE.</span><span>© 2026</span></footer>
    </div>
  </div>;
}

