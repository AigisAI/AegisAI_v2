import assert from 'node:assert/strict';
import { createExpoServer } from '../standalone/server.mjs';

const server = createExpoServer({ dbPath: ':memory:', publicOrigin: 'https://aegisai.tailaca7d2.ts.net' });
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
try {
  for (const path of ['/expo1', '/expo1/', '/expo2', '/expo2/']) {
    const response = await fetch(base + path);
    assert.equal(response.status, 200, path);
    assert.match(response.headers.get('content-type'), /text\/html/);
    const html = await response.text();
    const resources = [...html.matchAll(/(?:src|href)="(\/expo-assets\/[^"]+)"/g)].map((match) => match[1]);
    assert.ok(resources.some((resource) => resource.endsWith('.js')));
    assert.ok(resources.some((resource) => resource.endsWith('.css')));
    for (const resource of resources) {
      const asset = await fetch(base + resource);
      assert.equal(asset.status, 200, resource);
      if (resource.endsWith('.css')) assert.doesNotMatch(await asset.text(), /@(?:tailwind|theme|utility)\b/);
      if (resource.endsWith('.js')) {
        const js = await asset.text();
        assert.ok(js.includes('/expo-api/interest'));
        assert.ok(js.includes('출시해도 괜찮을까요'));
        assert.ok(js.includes('안전한 걸까요'));
      }
    }
  }
  console.log('Both production routes, styles, scripts, and same-origin interest path passed.');
} finally {
  await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
}
