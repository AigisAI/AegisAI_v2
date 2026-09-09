import { sql } from 'drizzle-orm';
import { getDb } from '@/db';
import { expoInterest } from '@/db/schema';
import { readInterestBody, validateInterestRequest } from '@/lib/interest-validation';

const COOKIE_NAME = 'aegis_expo_interest';
function json(body: object, status = 200, headers: Record<string, string> = {}) {
  return Response.json(body, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}

export async function POST(request: Request) {
  const invalid = validateInterestRequest(request);
  if (invalid) return json({ ok: false }, invalid);
  // The UI has no free-form fields. Reject extra input before touching storage.
  try {
    if (!await readInterestBody(request)) return json({ ok: false }, 400);
  } catch { return json({ ok: false }, 400); }
  const hasVoted = (request.headers.get('cookie') ?? '').split(';').some(
    (cookie) => cookie.trim() === `${COOKIE_NAME}=1`,
  );
  if (hasVoted) return json({ ok: true, alreadyRecorded: true });
  try {
    const day = new Date().toISOString().slice(0, 10);
    const recorded = await getDb().insert(expoInterest).values({ day, count: 1 }).onConflictDoUpdate({
      target: expoInterest.day,
      set: { count: sql`${expoInterest.count} + 1` },
      setWhere: sql`${expoInterest.count} < 10000`,
    }).returning({ count: expoInterest.count });
    if (!recorded.length) return json({ ok: false, message: '오늘 관심 접수가 많아요. 부스에서 이야기 나눠요.' }, 429);
    return json({ ok: true }, 200, {
      'Set-Cookie': `${COOKIE_NAME}=1; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000${new URL(request.url).protocol === 'https:' ? '; Secure' : ''}`,
    });
  } catch {
    return json({ ok: false, message: '잠시 후 다시 눌러주세요.' }, 503);
  }
}
