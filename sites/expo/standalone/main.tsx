import { createRoot } from 'react-dom/client';
import ExpoExperience from '../app/expo-experience';
import DirectExperience from '../app/direct-experience';
import SenseExperience from '../app/sense-experience';
import '../app/globals.css';

const isDirect = window.location.pathname.replace(/\/$/, '') === '/expo2';
const isSense = window.location.pathname.replace(/\/$/, '') === '/expo3';
document.title = isSense ? 'AegisAI · 내 보안 감각, 몇 점일까?' : isDirect ? 'AegisAI · 출시 전 보안 미션' : 'AegisAI · 30초 보안 체험';
if (isSense) document.querySelector('meta[name="theme-color"]')?.setAttribute('content', '#fa5d32');
createRoot(document.getElementById('root')!).render(
  isSense ? <SenseExperience interestEndpoint="/expo-api/interest" /> : isDirect ? <DirectExperience interestEndpoint="/expo-api/interest" /> : <ExpoExperience interestEndpoint="/expo-api/interest" />,
);
