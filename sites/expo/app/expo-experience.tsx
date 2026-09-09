'use client';

import { useEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowLeft, ArrowRight, Check, CheckCheck, CircleAlert, CodeXml, ExternalLink, Fingerprint, Heart, LockKeyhole, Package, RotateCcw, Share2, ShieldCheck, ShoppingBag, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';

const DEMO_URL = 'https://aegisai.tailaca7d2.ts.net/';
const steps = ['위험 발견', '수정 방향', '결과 확인'];
const headlines = [
  <>우리 쇼핑몰,<br /><span>출시해도 괜찮을까요?</span></>,
  <>내 주문을 찾다가,<br /><span>다른 주문까지?</span></>,
  <>작은 코드 차이,<br /><span>달라지는 보안.</span></>,
  <>위험을 이해했다면,<br /><span>이제 고칠 차례.</span></>,
];
const descriptions = ['주문 조회에 숨어 있는 위험을 찾아보세요.', '정상 작동하는 기능에도 위험이 숨어 있습니다.', '입력값을 명령과 분리하는 것이 핵심입니다.', '발견에서 수정 방향까지, 직접 확인했어요.'];

function OrderRow({ exposed = false }: { exposed?: boolean }) {
  return <div className={`order-row${exposed ? ' exposed' : ''}`}>
    <div className="order-icon"><Package size={22} strokeWidth={1.6} /></div>
    <div className="order-copy"><strong>{exposed ? '다른 고객의 주문' : '내 주문 · ORD-1024'}</strong><span>{exposed ? '조회되면 안 되는 주문 정보' : '클래식 셔츠 외 1건'}</span></div>
    {exposed ? <CircleAlert size={20} /> : <span className="order-status">배송 준비</span>}
  </div>;
}

export default function ExpoExperience({ interestEndpoint = '/api/interest' }: { interestEndpoint?: string }) {
  const [stage, setStage] = useState(0);
  const [codeOpen, setCodeOpen] = useState(false);
  const [interest, setInterest] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [shareMessage, setShareMessage] = useState('');
  const [shareUrl, setShareUrl] = useState('');
  const [manualShare, setManualShare] = useState(false);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const mounted = useRef(false);
  const interestInFlight = useRef(false);

  useEffect(() => {
    if (!mounted.current) { mounted.current = true; return; }
    titleRef.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'instant' });
  }, [stage]);

  function move(next: number) { setCodeOpen(false); setShareMessage(''); setManualShare(false); setStage(next); }
  async function recordInterest() {
    if (interestInFlight.current || interest === 'saved') return;
    interestInFlight.current = true;
    setInterest('saving');
    try {
      const response = await fetch(interestEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"interested":true}', signal: AbortSignal.timeout(12000) });
      const result: unknown = await response.json();
      if (!response.ok || typeof result !== 'object' || result === null || !('ok' in result) || result.ok !== true) throw new Error('Not recorded');
      setInterest('saved');
    } catch { setInterest('error'); }
    finally { interestInFlight.current = false; }
  }
  async function share() {
    const SHARE_URL = new URL('/expo1', window.location.origin).href;
    setShareUrl(SHARE_URL);
    setShareMessage('');
    if (navigator.share) {
      try { await navigator.share({ title: 'AegisAI · 30초 보안 점검 체험', text: '우리 쇼핑몰, 출시해도 괜찮을까요? 숨은 위험을 함께 확인해 보세요.', url: SHARE_URL }); return; }
      catch (error) { if (error instanceof Error && error.name === 'AbortError') return; }
    }
    try { await navigator.clipboard.writeText(SHARE_URL); setShareMessage('링크를 복사했어요. 원하는 곳에 붙여넣으세요.'); }
    catch { setManualShare(true); setShareMessage('아래 주소를 길게 눌러 복사해 주세요.'); }
  }

  return <div className="site-shell">
    <a className="skip-link" href="#experience">체험으로 바로가기</a>
    <header className="site-header"><button type="button" onClick={() => move(0)} style={{ border: 0, background: 'none', padding: 0, cursor: 'pointer' }} className="brand" aria-label="AegisAI 체험 첫 화면"><ShieldCheck aria-hidden="true" size={28} strokeWidth={2} /><span>Aegis<span className="brand-ai">AI</span></span></button><span className="expo-badge">EXPO <b>2026</b></span></header>
    <main id="experience" className="experience-layout">
      <div className="story-column">
        <div className="eyebrow"><span className="status-dot" />30초 보안 점검 <span className="eyebrow-divider">/</span> 직접 체험</div>
        <h1 tabIndex={-1} ref={titleRef}>{headlines[stage]}</h1><p className="lead">{descriptions[stage]}</p>
        <nav className="step-nav" aria-label="체험 진행 단계">{steps.map((label, index) => { const current = stage === 0 ? 0 : stage - 1; return <div key={label} className={`step-item${current === index ? ' current' : ''}${current > index ? ' complete' : ''}`} aria-current={current === index ? 'step' : undefined}><span className="step-number">{current > index ? <Check size={15} /> : `0${index + 1}`}</span><span>{label}</span></div>; })}</nav>
        <div className="desktop-aside"><span className="aside-rule" /><p>보안 경고를 발견하는 것에서<br />개발자가 이해하고 고치는 것까지.</p><span className="aside-caption">AegisAI Interactive Experience</span></div>
      </div>
      <div className="interaction-column" key={stage}>
        {stage === 0 && <section className="experience-card intro-card" aria-label="샘플 쇼핑몰 주문 조회">
          <div className="card-topline"><span><ShoppingBag size={17} /><b>DEMO SHOP</b><i>/</i>주문 조회</span><span className="sample-pill">샘플</span></div>
          <div className="shop-heading"><h2>주문을 확인해 볼까요?</h2><p>겉으로는 평범한 주문 조회 화면입니다.</p></div>
          <div className="order-field"><span>주문번호</span><div><code>ORD-1024</code><span className="field-check"><Check size={14} />조회 완료</span></div></div>
          <OrderRow /><div className="notice amber"><CircleAlert size={18} /><span>출시 전 확인이 필요해요</span></div>
          <Button className="primary-button" onClick={() => move(1)}>숨은 위험 확인하기<ArrowRight size={20} /></Button><p className="microcopy">샘플 데이터로 진행되는 체험입니다.</p>
        </section>}
        {stage === 1 && <section className="experience-card" aria-label="주문 조회의 보안 위험">
          <div className="card-topline"><span><CircleAlert size={17} /><b>위험 발견</b></span><span className="risk-pill">수정 필요</span></div>
          <h2 className="card-title">주문번호가 조회 명령을<br />바꿀 수 있다면?</h2><p className="card-description">입력값을 그대로 조회 명령에 붙이면, 의도하지 않은 주문 정보에 접근할 위험이 생깁니다.</p>
          <div className="exposure-demo"><OrderRow /><div className="flow-line"><ArrowDown size={18} /><span>잘못된 입력 처리로 생길 수 있는 일</span></div><OrderRow exposed /></div>
          <div className="finding-label"><CodeXml size={18} /><div><strong>SQL 삽입 · CWE-89</strong><span>주문 조회 코드의 보안 문제 예시</span></div></div>
          <Button className="primary-button" onClick={() => move(2)}>어떻게 고칠 수 있을까요?<ArrowRight size={20} /></Button><p className="microcopy">가상 상황을 설명한 화면이며 실제 공격은 실행하지 않습니다.</p>
        </section>}
        {stage === 2 && <section className="experience-card" aria-label="수정 전후 비교">
          <div className="card-topline"><span><Sparkles size={17} /><b>수정 방향</b></span><span className="sample-pill">AI 제안 예시</span></div>
          <h2 className="card-title">입력값은 입력값으로.<br />명령과 분리해요.</h2><p className="card-description">주문번호를 명령의 일부로 붙이지 않고, 정해진 자리에 값으로 전달합니다.</p>
          <Tabs defaultValue="after" className="comparison-tabs"><TabsList className="comparison-list" aria-label="수정 전후 선택"><TabsTrigger value="before">수정 전</TabsTrigger><TabsTrigger value="after">수정 예시</TabsTrigger></TabsList>
            <TabsContent value="before"><div className="comparison-box before"><CircleAlert size={26} /><strong>명령과 입력값이 섞여요</strong><div className="query-diagram"><span>조회 명령</span><b>+</b><span>입력값</span></div><p>입력값에 따라 명령의 의미가 달라질 위험이 있습니다.</p></div></TabsContent>
            <TabsContent value="after"><div className="comparison-box after"><ShieldCheck size={26} /><strong>명령과 입력값을 나눠요</strong><div className="query-diagram"><span>정해진 명령</span><LockKeyhole size={18} /><span>별도 입력값</span></div><p>명령의 구조를 유지하고 주문번호는 값으로만 처리합니다.</p></div></TabsContent>
          </Tabs>
          <Button className="code-toggle" variant="ghost" aria-expanded={codeOpen} aria-controls="code-example" onClick={() => setCodeOpen(!codeOpen)}><CodeXml size={17} />{codeOpen ? '코드 예시 접기' : '개발자라면, 코드로 보기'}<span>{codeOpen ? '−' : '+'}</span></Button>
          {codeOpen && <div id="code-example" className="code-example"><span>수정 전</span><pre><code>{'String sql = "SELECT * FROM orders WHERE id = " + orderId;'}</code></pre><span>수정 예시</span><pre><code>{'jdbcTemplate.queryForObject(\n  "SELECT * FROM orders WHERE id = ?",\n  orderMapper, orderId\n);'}</code></pre><p>파라미터 바인딩 예시입니다. 별도의 사용자 권한 검사와 테스트도 필요합니다.</p></div>}
          <div className="notice neutral"><Fingerprint size={20} /><span>제안은 자동 적용되지 않아요.<br />개발자의 검토와 재점검이 필요합니다.</span></div><Button className="primary-button" onClick={() => move(3)}>체험 결과 확인하기<ArrowRight size={20} /></Button>
        </section>}
        {stage === 3 && <section className="experience-card result-card" aria-label="체험 결과와 관심 표시">
          <div className="card-topline"><span><CheckCheck size={18} /><b>체험 완료</b></span><span className="success-pill">3 / 3</span></div><div className="completion-symbol"><ShieldCheck size={34} /></div>
          <h2 className="card-title">보안 경고가<br />다음 행동으로.</h2><p className="card-description">AegisAI는 분석 결과를 정리하고,<br />원인과 수정 방향을 이해하도록 돕습니다.</p>
          <ol className="takeaways"><li><span>01</span><div><strong>위험을 발견하고</strong><p>스캐너의 분석 결과와 근거를 확인합니다.</p></div></li><li><span>02</span><div><strong>수정 방향을 이해하고</strong><p>AI 설명을 참고해 개발자가 검토합니다.</p></div></li><li><span>03</span><div><strong>수정 후 다시 확인해요</strong><p>재점검은 실제 개발 과정에서 진행합니다.</p></div></li></ol>
          <div className="interest-section"><h3>우리 팀에도 필요할 것 같나요?</h3><Button className={`primary-button interest-button${interest === 'saved' ? ' is-saved' : ''}`} disabled={interest === 'saving' || interest === 'saved'} onClick={recordInterest}>{interest === 'saved' ? <Check size={20} /> : <Heart size={20} />}{interest === 'saving' ? '관심을 남기는 중…' : interest === 'saved' ? '관심을 남겼어요. 감사합니다!' : interest === 'error' ? '다시 관심 남기기' : '관심 있어요'}</Button><p className="microcopy">연락처 없이 관심 건수만 저장합니다.<br />파일럿 신청이나 알림 구독은 아닙니다.</p><output className="feedback-message">{interest === 'error' ? '저장하지 못했어요. 연결을 확인하고 다시 눌러주세요.' : interest === 'saved' ? '더 자세한 이야기는 전시 부스에서 나눠요.' : ''}</output></div>
          <div className="result-actions"><Button variant="outline" className="secondary-button" onClick={share}><Share2 size={18} />체험 공유하기</Button><a className="demo-link" href={DEMO_URL} target="_blank" rel="noopener noreferrer">전체 데모 보기<ExternalLink size={16} /></a></div>
          {shareMessage && <output className="share-message">{shareMessage}</output>}{manualShare && <input className="share-url" aria-label="공유할 페이지 주소" readOnly value={shareUrl} onFocus={(event) => event.target.select()} />}
        </section>}
        <div className="below-card">{stage > 0 ? <><Button variant="ghost" className="back-button" onClick={() => move(stage - 1)}><ArrowLeft size={16} />이전</Button><Button variant="ghost" className="back-button" onClick={() => move(0)}><RotateCcw size={16} />처음부터</Button></> : <span><LockKeyhole size={15} />개인정보 입력 없이 바로 체험</span>}</div>
      </div>
    </main>
    <footer className="site-footer"><span>AegisAI <span className="footer-divider">/</span> EXPO 2026</span><p>프로토타입 · 샘플 체험<br className="mobile-break" /><span className="desktop-separator"> · </span>실제 분석·AI 추론 결과가 아닙니다.</p></footer>
  </div>;
}





