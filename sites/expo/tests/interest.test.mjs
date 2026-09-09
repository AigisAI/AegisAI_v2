import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { validateInterestRequest, readInterestBody } from '../lib/interest-validation.ts';

function request(body = '{"interested":true}', headers = {}) {
  return new Request('https://expo.example/api/interest', { method: 'POST', headers: { origin: 'https://expo.example', 'content-type': 'application/json', ...headers }, body });
}
test('same-origin anonymous interest passes; cross-origin and missing origin fail', () => {
  assert.equal(validateInterestRequest(request()), null);
  assert.equal(validateInterestRequest(request(undefined, { origin: 'https://other.example' })), 403);
  const noOrigin = request(); noOrigin.headers.delete('origin');
  assert.equal(validateInterestRequest(noOrigin), 403);
  assert.equal(validateInterestRequest(request(undefined, { 'sec-fetch-site': 'cross-site' })), 403);
});
test('simple cross-site form types and declared oversized payloads are rejected', () => {
  assert.equal(validateInterestRequest(request(undefined, { 'content-type': 'text/plain' })), 415);
  assert.equal(validateInterestRequest(request(undefined, { 'content-length': '100000' })), 413);
});
test('only fixed anonymous body is accepted; contact fields and malformed JSON are rejected', async () => {
  assert.equal(await readInterestBody(request()), true);
  assert.equal(await readInterestBody(request('{"interested":true,"email":"person@example.com"}')), false);
  assert.equal(await readInterestBody(request('not-json')), false);
  assert.equal(await readInterestBody(request('')), false);
});
test('oversized streaming payload without content-length stops before consuming the whole stream', async () => {
  let canceled = false;
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(65)); }, cancel() { canceled = true; } });
  const streamed = new Request('https://expo.example/api/interest', { method: 'POST', body: stream, duplex: 'half' });
  assert.equal(await readInterestBody(streamed), false);
  assert.equal(canceled, true);
});
test('migration stores daily aggregates and atomic increments with a bounded daily quota', () => {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(new URL('../drizzle/0000_ambitious_preak.sql', import.meta.url), 'utf8'));
  const record = db.prepare('INSERT INTO expo_interest(day,count) VALUES (?,1) ON CONFLICT(day) DO UPDATE SET count=count+1 WHERE count < 10000 RETURNING count');
  assert.equal(record.get('2026-09-09').count, 1);
  assert.equal(record.get('2026-09-09').count, 2);
  assert.equal(record.get('2026-09-10').count, 1);
  db.exec("UPDATE expo_interest SET count=10000 WHERE day='2026-09-09'");
  assert.equal(record.get('2026-09-09'), undefined);
  assert.deepEqual(db.prepare('PRAGMA table_info(expo_interest)').all().map(row => row.name), ['day', 'count']);
  db.close();
});
