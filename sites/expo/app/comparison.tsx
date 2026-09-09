'use client';

import Link from 'next/link';
import { ArrowUpRight, Columns2, RotateCcw, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import './comparison.css';

const versions = [
  { key: 'a', route: '/expo1', label: 'A', title: 'Stitch 디자인 기반', description: '밝은 화면 · 차분한 설명 · 단계별 안내', tone: 'light' },
  { key: 'b', route: '/expo2', label: 'B', title: '직접 디자인', description: '어두운 화면 · 출시 전 미션 · 상황 중심 체험', tone: 'dark' },
];

export default function Comparison() {
  const [view, setView] = useState('both');
  const [revision, setRevision] = useState(0);
  return <main className="compare-shell">
    <header className="compare-header"><div><ShieldCheck size={25} /><strong>AegisAI</strong><span>디자인 비교</span></div><span className="compare-local">모바일 체험 · 두 가지 디자인</span></header>
    <section className="compare-intro"><div><p className="compare-kicker">TWO DIRECTIONS, ONE EXPERIENCE</p><h1>어떤 체험이 더 끌리나요?</h1><p>같은 보안 사례를 서로 다른 방식으로 구성했습니다. 각 화면을 직접 눌러 비교해 보세요.</p></div><Button variant="outline" onClick={() => setRevision(revision + 1)} className="compare-reset"><RotateCcw size={16} />둘 다 처음으로</Button></section>
    <div className="compare-toolbar"><Tabs value={view} onValueChange={(value) => setView(String(value))}><TabsList className="compare-tabs" aria-label="비교할 디자인 선택"><TabsTrigger value="both"><Columns2 size={16} />나란히</TabsTrigger><TabsTrigger value="a">A · Stitch</TabsTrigger><TabsTrigger value="b">B · 직접 디자인</TabsTrigger></TabsList></Tabs><span>모바일 화면 기준</span></div>
    <section className={`compare-grid view-${view}`} aria-label="디자인 시안 미리보기">
      {versions.map((version) => <article key={version.key} className={`compare-version version-${version.key}`} hidden={view !== 'both' && view !== version.key}>
        <div className="version-heading"><div><span className={`version-letter ${version.tone}`}>{version.label}</span><h2>{version.title}</h2></div><Link href={version.route} target="_blank" className="version-open">크게 보기<ArrowUpRight size={17} /></Link></div><p className="version-description">{version.description}</p>
        <div className={`phone-preview ${version.tone}`}><div className="phone-chrome"><span /><span /><span /></div><iframe key={`${version.key}-${revision}`} src={version.route} title={`${version.label}안 ${version.title} 모바일 체험`} allow="web-share" /></div>
      </article>)}
    </section>
    <footer className="compare-footer">비교 포인트: 첫 화면에서 눌러보고 싶은지 · 설명 없이 이해되는지 · 체험 후 제품이 기억나는지</footer>
  </main>;
}



