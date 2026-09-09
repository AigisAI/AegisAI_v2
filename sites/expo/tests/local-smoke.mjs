import assert from 'node:assert/strict';

const origin = 'http://localhost:3000';
for (const path of ['/', '/compare', '/stitch', '/direct', '/expo1', '/expo2', '/expo', '/api/health']) {
  const response = await fetch(origin + path);
  assert.equal(response.status, 200, `${path} must respond`);
}
const send = (options = {}) => fetch(`${origin}/api/interest`, {
  method: 'POST', headers: { origin, 'content-type': 'application/json', ...options.headers },
  body: options.body ?? '{"interested":true}',
});
assert.equal((await send({ headers: { origin: 'https://other.example' } })).status, 403);
assert.equal((await send({ body: '{"email":"not-stored@example.com"}' })).status, 400);
const first = await send();
assert.equal(first.status, 200);
assert.equal((await first.json()).ok, true);
const cookie = first.headers.get('set-cookie');
assert.ok(cookie?.includes('HttpOnly'));
assert.ok(cookie?.includes('SameSite=Strict'));
const duplicate = await send({ headers: { cookie: cookie.split(';')[0] } });
assert.equal(duplicate.status, 200);
assert.equal((await duplicate.json()).alreadyRecorded, true);
assert.equal((await fetch(`${origin}/api/interest`)).status, 405);
console.log('PASS: comparison and both design routes, database health, origin guard, fixed body, saved interest, duplicate protection, no public read endpoint.');

