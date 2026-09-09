import type { Metadata, Viewport } from 'next';
import './globals.css';
export const metadata: Metadata = {
  metadataBase: new URL('https://aegisai-expo.dewy-olm-7701.chatgpt.site'),
  title: 'AegisAI · 우리 쇼핑몰, 출시해도 괜찮을까요?',
  description: '30초 보안 점검 체험. 주문 조회에 숨은 위험을 발견하고 수정 방향까지 확인해 보세요. 가입 없이 샘플 데이터로 체험합니다.',
  icons: { icon: '/favicon.svg' },
  openGraph: { title: '우리 쇼핑몰, 출시해도 괜찮을까요?', description: 'AegisAI에서 30초 만에 숨은 위험과 수정 방향을 확인해 보세요.', locale: 'ko_KR', type: 'website', url: '/' },
};
export const viewport: Viewport = { width: 'device-width', initialScale: 1, themeColor: '#fbfbf9' };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="ko"><body>{children}</body></html>;
}
