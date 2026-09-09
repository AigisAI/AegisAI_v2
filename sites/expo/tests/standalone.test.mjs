import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createExpoServer } from '../standalone/server.mjs';

test('deployed adapter preserves votes across restart and isolates existing routes', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'aegis-expo-'));
  const dbPath = join(dir, 'interest.sqlite');
  const publicOrigin = 'https://aegisai.tailaca7d2.ts.net';
  let server;
  const start = async () => {
    server = createExpoServer({ dbPath, publicOrigin });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${server.address().port}`;
  };
  const stop = () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
  const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };
  try {
    let url = await start();
    assert.equal((await fetch(`${url}/expo-api/health`)).status, 200);
    for (const path of ['/', '/api/health', '/api/interest', '/expo-assets/../server.mjs', '/expo-assets/absent.js']) assert.equal((await fetch(url + path)).status, 404);
    assert.equal((await fetch(`${url}/expo-api/interest`)).status, 405);
    for (const origin of ['', 'https://evil.example']) assert.equal((await fetch(`${url}/expo-api/interest`, { method: 'POST', headers: { ...headers, Origin: origin }, body: '{"interested":true}' })).status, 403);
    assert.equal((await fetch(`${url}/expo-api/interest`, { method: 'POST', headers, body: '{"email":"person@example.com"}' })).status, 400);
    const vote = await fetch(`${url}/expo-api/interest`, { method: 'POST', headers, body: '{"interested":true}' });
    assert.equal(vote.status, 200);
    assert.match(vote.headers.get('set-cookie'), /Path=\/expo-api; HttpOnly; SameSite=Strict;.*Secure/);
    assert.deepEqual(await (await fetch(`${url}/expo-api/interest`, { method: 'POST', headers: { ...headers, Cookie: 'aegis_expo_interest=1' }, body: '{"interested":true}' })).json(), { ok: true, alreadyRecorded: true });
    await stop();
    const db = new DatabaseSync(dbPath);
    assert.equal(db.prepare('SELECT count FROM expo_interest').get().count, 1);
    db.exec('UPDATE expo_interest SET count=10000');
    db.close();
    url = await start();
    assert.equal((await fetch(`${url}/expo-api/interest`, { method: 'POST', headers, body: '{"interested":true}' })).status, 429);
  } finally { if (server?.listening) await stop(); await rm(dir, { recursive: true }); }
});
