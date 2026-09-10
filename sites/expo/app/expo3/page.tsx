import type { Metadata } from 'next';
import SenseExperience from '../sense-experience';

export const metadata: Metadata = { metadataBase: new URL('https://aegisai.tailaca7d2.ts.net'), title: 'AegisAI · 내 보안 감각, 몇 점일까?', description: '세 가지 상황으로 알아보는 보안 감각. 골라보고, 이유를 알아보세요.', openGraph: { title: '내 보안 감각, 몇 점일까?', description: '세 가지 상황으로 알아보는 보안 감각.', url: '/expo3' } };
export default function ExpoThree() { return <SenseExperience />; }
