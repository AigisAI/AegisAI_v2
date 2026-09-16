# Expo3 booth operation

Visitor URL: https://aegisai.tailaca7d2.ts.net/expo3

## Visitor flow

1. Visitors scan the printed QR with their own phone and answer three questions.
2. Mobile progress controls stay at the bottom. Revealing an answer brings its explanation into view; advancing focuses the next question.
3. The result introduces AegisAI and offers a short, clearly labeled illustrative Java remediation sample. This sample runs locally in the page and does not call the scanner or an AI model.
4. Staff show the actual analysis workflow on the booth monitor. The product homepage link is labeled as a homepage, not an interactive demo.

## Shared tablet

Use “다시 풀어보기” between visitors. It clears answers, the score, and the sample view. Interest remains recorded for the browser for 30 days; it is not a per-visitor counter. All three expo versions share that cookie and daily aggregate. Use visitors' own phones for ordinary interest expressions; do not clear cookies between visitors to inflate the tally.

## Opening checks

- Scan the actual printed QR on iPhone Safari and Android Chrome using mobile data; confirm it reaches `/expo3` without login.
- Complete the quiz, open the sample, switch to the suggested change, and restart on both devices. Check portrait, landscape, and larger text.
- Bring an independent hotspot and a charged backup phone. Initial page loading and interest submission require internet. There is no offline installation or cache guarantee.
- Open the monitor demonstration before doors open. Prepare a local recording or screenshots of the demonstration as a connectivity fallback. These need to be captured from the actual demonstration environment; they are not supplied by this page.
- Explain that the code sample is educational and AI suggestions require developer review. Interest is neither a pilot application nor a subscription, and no contact details are collected.

## Validation for changes

From `sites/expo`: `corepack pnpm lint`, `corepack pnpm exec tsc --noEmit`, `corepack pnpm build:standalone`, `corepack pnpm test`, and `node tests/standalone-smoke.mjs`. Browser checks should cover wrong and correct answers, the score, focus/scroll behavior, fixed controls, sample toggling, and reset at mobile and desktop widths. The existing GitHub CI/CD pipeline is the deployment path.
