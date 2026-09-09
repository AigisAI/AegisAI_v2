import { getDb } from '@/db';
import { expoInterest } from '@/db/schema';

export async function GET() {
  try {
    await getDb().select({ day: expoInterest.day }).from(expoInterest).limit(1);
    return Response.json({ ok: true }, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return Response.json({ ok: false }, { status: 503, headers: { 'Cache-Control': 'no-store' } });
  }
}
