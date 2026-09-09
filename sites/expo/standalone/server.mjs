import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { dirname, resolve, extname, sep } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Readable } from 'node:stream';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readInterestBody, validateInterestRequest } from '../lib/interest-validation.ts';

const COOKIE = 'aegis_expo_interest';
const defaultStatic = fileURLToPath(new URL('../dist-standalone', import.meta.url));
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };

export function createExpoServer({ dbPath, publicOrigin, staticDirectory = defaultStatic }) {
  const origin = new URL(publicOrigin).origin;
  if (dbPath !== ':memory:') mkdirSync(dirname(resolve(dbPath)), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS expo_interest (day TEXT PRIMARY KEY NOT NULL, count INTEGER NOT NULL DEFAULT 0);');
  const record = db.prepare('INSERT INTO expo_interest (day, count) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET count=count+1 WHERE count<10000 RETURNING count');
  const health = db.prepare('SELECT count FROM expo_interest LIMIT 1');
  let windowStart = Date.now();
  let attempts = 0;
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 15000, headersTimeout: 10000 }, async (req, res) => {
    const json = (status, body, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers });
      res.end(JSON.stringify(body));
    };
    try {
      const pathname = new URL(req.url, origin).pathname;
      if (pathname === '/expo-api/health' && req.method === 'GET') {
        health.get();
        return json(200, { ok: true });
      }
      if (pathname === '/expo-api/interest') {
        if (req.method !== 'POST') return json(405, { ok: false }, { Allow: 'POST' });
        if (Date.now() - windowStart >= 60000) { windowStart = Date.now(); attempts = 0; }
        if (++attempts > 120) return json(429, { ok: false }, { 'Retry-After': '60' });
        // Validate against the configured public origin, never a client-supplied forwarded host.
        const request = new Request(`${origin}/expo-api/interest`, { method: 'POST', headers: req.headers, body: Readable.toWeb(req), duplex: 'half' });
        const invalid = validateInterestRequest(request);
        if (invalid) return json(invalid, { ok: false });
        try {
          if (!await readInterestBody(request)) return json(400, { ok: false });
        } catch { return json(400, { ok: false }); }
        if ((req.headers.cookie ?? '').split(';').some((cookie) => cookie.trim() === `${COOKIE}=1`)) return json(200, { ok: true, alreadyRecorded: true });
        const recorded = record.get(new Date().toISOString().slice(0, 10));
        if (!recorded) return json(429, { ok: false });
        return json(200, { ok: true }, { 'Set-Cookie': `${COOKIE}=1; Path=/expo-api; HttpOnly; SameSite=Strict; Max-Age=2592000${origin.startsWith('https:') ? '; Secure' : ''}` });
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') return json(405, { ok: false });
      let relative;
      if (/^\/expo[12]\/?$/.test(pathname)) relative = 'index.html';
      else if (pathname.startsWith('/expo-assets/')) relative = decodeURIComponent(pathname.slice('/expo-assets/'.length));
      else return json(404, { ok: false });
      const root = resolve(staticDirectory);
      const file = resolve(root, relative);
      if (!file.startsWith(`${root}${sep}`) || !mime[extname(file)]) return json(404, { ok: false });
      let content;
      try { content = await readFile(file); } catch { return json(404, { ok: false }); }
      res.writeHead(200, {
        'Content-Type': mime[extname(file)],
        'Cache-Control': relative.startsWith('assets/') ? 'public, max-age=31536000, immutable' : 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'",
      });
      res.end(req.method === 'HEAD' ? undefined : content);
    } catch { if (!res.headersSent) json(503, { ok: false }); else res.end(); }
  });
  server.on('close', () => db.close());
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (!process.env.EXPO_PUBLIC_ORIGIN) throw new Error('EXPO_PUBLIC_ORIGIN is required');
  const server = createExpoServer({ dbPath: process.env.EXPO_DATA_PATH ?? '/data/interest.sqlite', publicOrigin: process.env.EXPO_PUBLIC_ORIGIN });
  server.listen(Number(process.env.PORT ?? 3100), '0.0.0.0', () => console.log('EXPO server ready'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => server.close());
}
