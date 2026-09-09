import { createRoot } from 'react-dom/client';
import ExpoExperience from '../app/expo-experience';
import DirectExperience from '../app/direct-experience';
import '../app/globals.css';

const isDirect = window.location.pathname.replace(/\/$/, '') === '/expo2';
document.title = isDirect ? 'AegisAI · 출시 전 보안 미션' : 'AegisAI · 30초 보안 체험';
createRoot(document.getElementById('root')!).render(
  isDirect ? <DirectExperience interestEndpoint="/expo-api/interest" /> : <ExpoExperience interestEndpoint="/expo-api/interest" />,
);
