/**
 * End-to-end test of the MCP tool path against a LOCAL STUB of /v1/sends.
 *
 * Needs no API key and no running FileSeal instance. That is what separates it
 * from the live integration tests kept in the private FileSeal repo (which
 * need a real key and a running instance) and what makes it safe to run in
 * this repository's CI.
 *
 * What it proves that the unit tests cannot: that driving the real MCP server
 * through a real MCP client produces the correct HTTP request. In particular
 * the ZERO-KNOWLEDGE INVARIANT — link mode must NOT send encryptionKey, email
 * mode must — which is a property of the request body, not of any one function.
 *
 * Run:  node stub-e2e.mjs
 */
import { createServer } from 'node:http';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

let failures = 0;
const ok = (cond, msg) => {
  if (cond) { console.log('  ok  ' + msg); } else { console.error('  FAIL  ' + msg); failures++; }
};

// --- stub /v1/sends -------------------------------------------------------
const requests = [];
const stub = createServer((req, res) => {
  // Buffers, not string concatenation: `body += chunk` decodes each chunk
  // independently, so a multi-byte UTF-8 character split across a chunk
  // boundary is corrupted. The parse is guarded too — an uncaught throw in an
  // 'end' handler kills the server mid-request, and the run hangs waiting for
  // a response instead of reporting a failed assertion.
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    let parsed = null;
    let parseError = null;
    try {
      parsed = raw ? JSON.parse(raw) : null;
    } catch (err) {
      parseError = err.message;
    }
    requests.push({
      method: req.method,
      url: req.url,
      auth: req.headers.authorization,
      body: parsed,
      parseError,
    });
    res.setHeader('content-type', 'application/json');
    if (req.method === 'POST') {
      res.end(JSON.stringify({
        success: true, id: 'stub-send-id', claimUrl: 'https://fileseal.uk/receive/stub-send-id',
        expiresAt: '2026-09-05T00:00:00.000Z', filesCount: 1, totalSize: 42, emailSent: true,
      }));
    } else if (req.method === 'DELETE') {
      // Mirrors production, measured against fileseal.uk. DELETE is not
      // symmetric with GET: 404 is ONLY a malformed id; a well-formed UUID that
      // does not exist returns 409, indistinguishable from 'collected'. The
      // first version of this stub asserted unknown -> 404, which ratified a
      // false claim in the tool description because the only case it exercised
      // was a non-UUID.
      if (req.url.includes('collected-id')) {
        res.statusCode = 409;
        res.end(JSON.stringify({ error: 'Send cannot be revoked (already collected, already revoked, or not found).' }));
      } else if (req.url.includes('069b31db-461d-47e4-82c1-771f08fb0b95')) {
        // A well-formed UUID that does not exist: the realistic case.
        res.statusCode = 409;
        res.end(JSON.stringify({ error: 'Send cannot be revoked (already collected, already revoked, or not found).' }));
      } else if (req.url.includes('not-a-uuid')) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Send not found.' }));
      } else if (req.url.includes('bare-404')) {
        // A 404 with NO error body: what a misconfigured origin returns, rather
        // than this API answering. Must not be reported as a malformed id.
        res.statusCode = 404;
        res.end('');
      } else {
        res.end(JSON.stringify({ success: true, id: 'stub-send-id', status: 'revoked' }));
      }
    } else {
      res.end(JSON.stringify({
        id: 'stub-send-id', status: 'pending', deliveryMode: 'link', createdAt: 'x',
        expiresAt: 'y', downloadCount: 0, filesCount: 1, events: [{ action: 'created', createdAt: 'z' }],
      }));
    }
  });
});
await new Promise((r) => stub.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${stub.address().port}`;

// --- drive the real server through a real client --------------------------
const transport = new StdioClientTransport({
  command: 'node',
  args: ['index.mjs'],
  env: { ...process.env, FILESEAL_API_KEY: 'stub-key', FILESEAL_API_BASE_URL: base },
});
const client = new Client({ name: 'stub-e2e', version: '0.0.0' });
await client.connect(transport);

const text = (r) => (r.content || []).map((c) => c.text || '').join('\n');
const dir = mkdtempSync(join(tmpdir(), 'fileseal-e2e-'));
const file = join(dir, 'sample.pdf');
writeFileSync(file, '%PDF-1.4\nstub e2e\n%%EOF\n');

console.log('link mode (zero-knowledge)');
{
  const res = await client.callTool({ name: 'secure_send', arguments: { filePath: file, deliveryMode: 'link' } });
  const out = text(res);
  const sent = requests.at(-1);
  ok(!res.isError, 'tool did not error');
  ok(sent.method === 'POST' && sent.url === '/v1/sends', 'POST /v1/sends');
  ok(sent.auth === 'Bearer stub-key', 'bearer token forwarded');
  ok(sent.body.deliveryMode === 'link', 'deliveryMode link');
  ok(sent.body.files[0].encryptionKey === undefined, 'ZERO-KNOWLEDGE: no encryptionKey in the request');
  ok(typeof sent.body.files[0].ciphertextBase64 === 'string' && sent.body.files[0].ciphertextBase64.length > 0, 'ciphertext sent');
  ok(sent.body.files[0].mimeType === 'application/pdf', 'mimeType inferred from the extension');
  ok(sent.body.files[0].filename === 'sample.pdf', 'filename inferred from the path');
  const iv = Buffer.from(sent.body.files[0].ciphertextBase64, 'base64');
  ok(iv.length > 12, 'ciphertext is longer than the 12-byte IV');
  const frag = /#k=([A-Za-z0-9_-]+)$/.exec(out.match(/Share link: (\S+)/)?.[1] ?? '');
  ok(!!frag, 'share link carries a base64url #k= fragment');
  ok(frag && Buffer.from(frag[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').length === 32, 'fragment decodes to a 32-byte AES-256 key');
  ok(!out.includes('stub-key'), 'the API key is not echoed back to the model');
}

console.log('email mode');
{
  const res = await client.callTool({
    name: 'secure_send',
    arguments: { filePath: file, deliveryMode: 'email', recipientEmail: 'someone@example.com' },
  });
  const sent = requests.at(-1);
  ok(!res.isError, 'tool did not error');
  ok(sent.body.deliveryMode === 'email', 'deliveryMode email');
  ok(typeof sent.body.files[0].encryptionKey === 'string', 'email mode DOES send the key (server must decrypt to email a working link)');
  ok(sent.body.recipientEmail === 'someone@example.com', 'recipient forwarded');
  ok(!text(res).includes('#k='), 'no zero-knowledge link claimed in email mode');
}

console.log('input validation (no request should reach the API)');
{
  const before = requests.length;
  const cases = [
    [{ deliveryMode: 'link' }, /provide either filePath or fileBase64/, 'neither filePath nor fileBase64'],
    [{ fileBase64: 'aGk=', deliveryMode: 'link' }, /filename and mimeType/, 'fileBase64 without filename/mimeType'],
    [{ filePath: file, deliveryMode: 'email' }, /recipientEmail is required/, 'email mode without a recipient'],
    [{ filePath: join(dir, 'missing.pdf'), deliveryMode: 'link' }, /Error reading file/, 'unreadable path'],
  ];
  for (const [args, pattern, label] of cases) {
    const res = await client.callTool({ name: 'secure_send', arguments: args });
    ok(res.isError === true && pattern.test(text(res)), label);
  }
  ok(requests.length === before, 'no HTTP request was made for any invalid input');
}

console.log('empty file');
{
  const empty = join(dir, 'empty.pdf');
  writeFileSync(empty, '');
  const before = requests.length;
  const res = await client.callTool({ name: 'secure_send', arguments: { filePath: empty, deliveryMode: 'link' } });
  ok(res.isError === true && /empty or could not be read/.test(text(res)), 'rejected an empty file');
  ok(requests.length === before, 'and sent nothing');
}

console.log('send_status and revoke_send');
{
  const s = await client.callTool({ name: 'send_status', arguments: { id: 'stub-send-id' } });
  ok(!s.isError && requests.at(-1).method === 'GET' && requests.at(-1).url === '/v1/sends/stub-send-id', 'GET /v1/sends/:id');
  const r = await client.callTool({ name: 'revoke_send', arguments: { id: 'stub-send-id' } });
  ok(!r.isError && requests.at(-1).method === 'DELETE', 'DELETE /v1/sends/:id');
  // Assert the ENCODED path exactly. A negative match cannot work here: drop
  // encodeURIComponent and WHATWG URL normalises `/v1/sends/a b/../c` down to
  // `/v1/sends/c` before the request is sent, so the id traverses out of the
  // collection AND the old negative assertion still passed. Proven by mutation.
  const beforeEnc = requests.length;
  await client.callTool({ name: 'send_status', arguments: { id: 'a b/../c' } });
  ok(requests.length === beforeEnc + 1, 'the encoding check is looking at a NEW request');
  ok(
    requests.at(-1).url === '/v1/sends/a%20b%2F..%2Fc',
    `the id is percent-encoded into one path segment (got ${requests.at(-1).url})`
  );

  const twice = await client.callTool({ name: 'revoke_send', arguments: { id: 'stub-send-id' } });
  ok(!twice.isError && /revoked/.test(text(twice)), 'revoking an already-revoked send succeeds (idempotent)');
  const collected = await client.callTool({ name: 'revoke_send', arguments: { id: 'collected-id' } });
  ok(collected.isError === true, '409 is reported as an error');
  // The realistic miss: a well-formed UUID that does not exist also 409s, so the
  // tool must NOT tell the model the document was collected.
  const gone = await client.callTool({ name: 'revoke_send', arguments: { id: '069b31db-461d-47e4-82c1-771f08fb0b95' } });
  ok(gone.isError === true, 'a well-formed unknown UUID is an error');
  ok(/not found/.test(text(gone)), 'and its message admits the send may simply not exist');
  const malformed = await client.callTool({ name: 'revoke_send', arguments: { id: 'not-a-uuid' } });
  ok(malformed.isError === true && /not a valid send id/i.test(text(malformed)), '404 WITH an api error body is reported as a malformed id');
  ok(!/HTTP 404/.test(text(malformed)), 'and not as a raw HTTP error');
  const bare = await client.callTool({ name: 'revoke_send', arguments: { id: 'bare-404' } });
  ok(bare.isError === true, 'a bodyless 404 is still an error');
  ok(!/not a valid send id/i.test(text(bare)), 'but is NOT blamed on the id — that would misdirect the model');
  ok(/FILESEAL_API_BASE_URL/.test(text(bare)), 'it points at the base URL instead');
}

await client.close();
stub.close();
console.log(failures === 0 ? '\nSTUB E2E PASSED' : `\nSTUB E2E FAILED (${failures})`);
process.exit(failures === 0 ? 0 : 1);
