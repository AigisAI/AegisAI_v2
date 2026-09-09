export function validateInterestRequest(request: Request): number | null {
  const origin = request.headers.get('origin');
  if (!origin || origin !== new URL(request.url).origin) return 403;
  if (request.headers.get('sec-fetch-site') === 'cross-site') return 403;
  if (request.headers.get('content-type') !== 'application/json') return 415;
  const contentLength = request.headers.get('content-length');
  if (contentLength && Number(contentLength) > 64) return 413;
  return null;
}

export async function readInterestBody(request: Request): Promise<boolean> {
  if (!request.body) return false;
  const reader = request.body.getReader();
  let size = 0;
  let body = '';
  const decoder = new TextDecoder();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 64) { await reader.cancel(); return false; }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
    return body === '{"interested":true}';
  } finally { reader.releaseLock(); }
}
