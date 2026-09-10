'use client';

import { useEffect, useRef, useState } from 'react';
import { ArrowRight, ArrowUpRight, Check, CheckCheck, Heart, RotateCcw, Share2, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import './sense.css';

const questions = [
  {
    category: '비밀의 위치', title: '화면에 안 보이면, 비밀일까요?',
    situation: '개발자가 서비스의 비밀 API 키를 웹사이트 코드 안에 넣었습니다. 화면에는 표시되지 않아요.',
    clue: ['브라우저에 전달된 코드', '비밀 API 키 포함'],
    options: ['화면에 안 보이니 괜찮아요', '브라우저에 전달되면 노출될 수 있어요'], correct: 1,
    takeaway: '숨기는 것과 보호하는 것은 달라요.',
    explanation: '브라우저로 전달되는 코드와 요청은 사용자가 살펴볼 수 있어요. 비밀 키는 서버에서 관리하고, 이미 노출됐다면 폐기하고 새로 발급해야 합니다.',
    summary: '비밀 키는 브라우저 밖에서 관리하기',
  },
  {
    category: '접근의 경계', title: '로그인했으면, 다 봐도 될까요?',
    situation: '로그인한 회원이 주문 상세 페이지를 열었어요. 이 주문이 본인 것인지 어디에서 확인해야 할까요?',
    clue: ['로그인 확인 ✓', '주문의 주인 확인 ?'],
    options: ['서버가 요청마다 소유권을 확인해요', '화면에서 다른 주문 링크만 숨겨요'], correct: 0,
    takeaway: '로그인과 접근 권한은 별개예요.',
    explanation: '누구인지 확인했다고 모든 정보를 볼 수 있는 건 아니에요. 서버는 각 요청에서 해당 사용자가 그 주문에 접근할 권한이 있는지 확인해야 합니다.',
    summary: '정보를 내주기 전에 접근 권한 확인하기',
  },
  {
    category: '입력의 역할', title: '입력값을, 얼마나 믿어도 될까요?',
    situation: '검색어를 데이터베이스 조회 명령에 그대로 붙이고 있어요. 어떤 수정이 위험을 줄일까요?',
    clue: ['조회 명령', '+ 사용자가 입력한 검색어'],
    options: ['입력창에 주의 문구를 붙여요', '명령과 입력값을 분리해서 전달해요'], correct: 1,
    takeaway: '입력값은 데이터로만 다뤄야 해요.',
    explanation: '문자열을 그대로 붙이면 입력이 조회 명령의 의미를 바꿀 수 있어요. 매개변수화된 쿼리로 명령 구조와 값을 분리하는 것이 핵심입니다.',
    summary: '조회 명령과 입력값을 분리하기',
  },
];

export default function SenseExperience({ interestEndpoint = '/api/interest' }: { interestEndpoint?: string }) {
  const [index, setIndex] = useState(0);
  const [answers, setAnswers] = useState<(number | null)[]>([null, null, null]);
  const [revealed, setRevealed] = useState(false);
  const [finished, setFinished] = useState(false);
  const [interest, setInterest] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [shareMessage, setShareMessage] = useState('');
  const [manualUrl, setManualUrl] = useState('');
  const saving = useRef(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const firstRender = useRef(true);
  const question = questions[index];
  const selected = answers[index];
  const score = answers.reduce<number>((total, answer, i) => total + Number(answer === questions[i].correct), 0);

  useEffect(() => {
    if (firstRender.current) { firstRender.current = false; return; }
    heading.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'instant' });
  }, [index, finished]);

  function reset() {
    setAnswers([null, null, null]); setIndex(0); setRevealed(false); setFinished(false);
    setShareMessage(''); setManualUrl('');
  }
  function advance() {
    if (index === questions.length - 1) setFinished(true);
    else { setIndex(index + 1); setRevealed(false); }
  }
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
    const url = new URL('/expo3', window.location.origin).href;
    setManualUrl(''); setShareMessage('');
    if (navigator.share) {
      try { await navigator.share({ title: '내 보안 감각, 몇 점일까?', text: '세 가지 상황으로 알아보는 보안 감각. AegisAI와 함께 풀어보세요.', url }); return; }
      catch (error) { if (error instanceof Error && error.name === 'AbortError') return; }
    }
    try { await navigator.clipboard.writeText(url); setShareMessage('링크를 복사했어요. 친구에게 보내보세요.'); }
    catch { setManualUrl(url); setShareMessage('아래 주소를 길게 눌러 복사해 주세요.'); }
  }

  return <div className="sense-page">
    <a className="sense-skip" href="#sense-main">퀴즈로 바로가기</a>
    <div className="sense-shell">
      <header className="sense-header"><a className="sense-brand" href="https://aegisai.tailaca7d2.ts.net/" aria-label="AegisAI 데모 홈페이지"><ShieldCheck size={23} strokeWidth={2.5} /><span>AegisAI<span className="sense-brand-star" aria-hidden="true">✳</span></span></a><span className="sense-edition">THE SECURITY QUIZ<br /><b>EXPO EDITION / 2026</b></span></header>
      <main id="sense-main">
        <section className="sense-intro" aria-label="보안 감각 테스트">
          <div><p className="sense-eyebrow">생각보다 가까운 보안 이야기</p><h1>{finished ? <>이제, 위험이<br />조금 보이나요?</> : <>내 보안 감각,<br /><span>몇 점일까?</span></>}</h1><p className="sense-intro-copy">{finished ? '오늘 발견한 세 가지를 기억해 보세요.' : '세 가지 상황. 당신이라면 어떤 선택을 할까요?'}</p></div>
          <div className="sense-count" aria-hidden="true"><span>{finished ? 'YOUR SCORE' : 'JUST'}</span><strong>{finished ? score : '03'}</strong><span>{finished ? 'OUT OF 3' : 'QUESTIONS'}</span></div>
        </section>

        {!finished ? <section className="sense-sheet" aria-labelledby="sense-question" key={index}>
          <div className="sense-sheet-top"><span>QUESTION 0{index + 1}</span><ol aria-label="퀴즈 진행 상황">{questions.map((item, i) => <li key={item.category} className={i === index ? 'current' : i < index ? 'done' : ''} aria-current={i === index ? 'step' : undefined}><span className="sense-sr">{i + 1}번 문제 {i < index ? '완료' : ''}</span>{i < index ? <Check size={14} aria-hidden="true" /> : <span aria-hidden="true">{i + 1}</span>}</li>)}</ol><span className="sense-category">{question.category}</span></div>
          <div className="sense-question-body"><h2 id="sense-question" ref={heading} tabIndex={-1}>{question.title}</h2><p className="sense-situation">{question.situation}</p>
            <div className="sense-clue" aria-label="상황 요약"><span>{question.clue[0]}</span><span aria-hidden="true">/</span><strong>{question.clue[1]}</strong></div>
            <RadioGroup value={selected === null ? '' : String(selected)} onValueChange={(value) => { if (!revealed) setAnswers(answers.map((answer, i) => i === index ? Number(value) : answer)); }} disabled={revealed} aria-labelledby="sense-question" className="sense-options">
              {question.options.map((option, i) => <label key={option} className={`sense-option${selected === i ? ' selected' : ''}${revealed && i === question.correct ? ' correct' : ''}${revealed && selected === i && i !== question.correct ? ' missed' : ''}`}><RadioGroupItem value={String(i)} className="sense-radio" /><span className="sense-option-letter" aria-hidden="true">{i === 0 ? 'A' : 'B'}</span><span className="sense-option-text">{option}</span>{revealed && i === question.correct && <Check size={20} aria-label="정답" />}</label>)}
            </RadioGroup>
            {revealed && <div className="sense-answer" aria-live="polite" aria-atomic="true"><span className="sense-answer-tag">{selected === question.correct ? '좋은 감각이에요!' : '이렇게 생각해 보세요'}</span><h3>{question.takeaway}</h3><p>{question.explanation}</p></div>}
          </div>
          <div className="sense-sheet-bottom"><p>{revealed ? '작은 차이가, 큰 위험을 만들 수 있어요.' : '정답을 몰라도 괜찮아요. 일단 골라보세요.'}</p><Button className="sense-primary" disabled={!revealed && selected === null} onClick={revealed ? advance : () => setRevealed(true)}>{revealed ? index === 2 ? '내 결과 보기' : '다음 상황으로' : '정답 확인'}<ArrowRight size={19} /></Button></div>
        </section> : <section className="sense-sheet sense-result" aria-labelledby="sense-result-heading">
          <div className="sense-sheet-top"><span>YOUR TAKEAWAYS</span><span className="sense-result-stamp"><CheckCheck size={17} />체험 완료</span></div>
          <div className="sense-result-body"><div className="sense-result-lead"><p className="sense-score-label">3문제 중 <strong>{score}문제</strong>를 맞혔어요.</p><h2 id="sense-result-heading" ref={heading} tabIndex={-1}>{score === 3 ? '좋은 감각에, 근거를 더하세요.' : '점수보다 중요한 건, 다음 선택.'}</h2><p>코드 속 위험도 발견에서 끝나지 않아야 하니까요.<br />AegisAI가 만드는 발견과 수정 검토의 흐름을 만나보세요.</p></div>
            <ol className="sense-takeaways">{questions.map((item, i) => <li key={item.category}><span>0{i + 1}</span><div><small>{item.category}</small><strong>{item.summary}</strong></div><Check size={21} aria-hidden="true" /></li>)}</ol>
            <div className="sense-result-actions"><Button className="sense-primary" disabled={interest === 'saving' || interest === 'saved'} onClick={expressInterest}>{interest === 'saved' ? <Check size={18} /> : <Heart size={18} />}{interest === 'saved' ? '관심을 남겼어요' : interest === 'saving' ? '남기는 중…' : interest === 'error' ? '관심 표시 다시 시도' : 'AegisAI, 관심 있어요'}</Button><Button variant="outline" className="sense-secondary" onClick={share}><Share2 size={18} />친구에게 문제 내기</Button></div>
            <p className="sense-interest-note" aria-live="polite" aria-atomic="true">{interest === 'saved' ? '고마워요. 개인정보 없이 관심 횟수만 기록했어요.' : interest === 'error' ? '관심 표시를 저장하지 못했어요. 다시 눌러 주세요.' : '개인정보 없이 관심만 남겨요. 신청이나 구독이 아닙니다.'}</p>
            {shareMessage && <p className="sense-share-message" aria-live="polite" aria-atomic="true">{shareMessage}</p>}{manualUrl && <input className="sense-share-input" aria-label="공유할 체험 주소" readOnly value={manualUrl} onFocus={(event) => event.currentTarget.select()} />}
          </div>
          <div className="sense-sheet-bottom"><Button variant="ghost" className="sense-restart" onClick={reset}><RotateCcw size={16} />다시 풀어보기</Button><a className="sense-demo" href="https://aegisai.tailaca7d2.ts.net/" target="_blank" rel="noopener noreferrer">AegisAI 데모 보기<ArrowUpRight size={19} /></a></div>
        </section>}
        <footer className="sense-footer"><span>작은 의심이,<br /><b>더 안전한 코드를 만듭니다.</b></span><p>학습을 위한 가상 상황입니다.<br />실제 보안 진단이나 역량 평가가 아닙니다.</p></footer>
      </main>
    </div>
  </div>;
}

