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
import { writeFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
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
      raw,
      parseError,
    });
    res.setHeader('content-type', 'application/json');
    if (req.method === 'POST') {
      // A non-2xx POST is the likeliest real failure (402 plan gate, 429 cap).
      // Without this the error branch was dead: deleting it left the tool
      // telling the model "Share link: undefined#k=...".
      if (raw.includes('deny.pdf')) {
        res.statusCode = 402;
        res.end(JSON.stringify({ error: 'Upgrade required to use the send API.' }));
        return;
      }
      res.end(JSON.stringify({
        success: true, id: 'stub-send-id', claimUrl: 'https://fileseal.uk/receive/stub-send-id',
        ...(raw.includes('bounce@example.com') ? { emailSent: false } : {}),
        expiresAt: '2026-09-05T00:00:00.000Z', filesCount: 1, totalSize: 42,
        ...(raw.includes('bounce@example.com') ? {} : { emailSent: true }),
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
        // A well-formed UUID that does not exist: the realistic case. Answered
        // with an EMPTY body on purpose, so the assertions below observe the
        // CLIENT's fallback wording. When this branch returned the server's own
        // "...or not found" string, the /not found/ assertion matched THAT and
        // passed even when the client's fallback was mutated to claim the
        // document had been collected.
        res.statusCode = 409;
        res.end(JSON.stringify({}));
      } else if (req.url.includes('not-a-uuid')) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Send not found.' }));
      } else if (req.url.includes('html-404')) {
        // What a WRONG BASE URL actually returns: an HTML error page. readJson
        // coerces it to { error: '<!DOCTYPE...' }, so a discriminator based on
        // "is data.error a non-empty string" called this a malformed id — the
        // exact misdirection the branch exists to prevent, and the common case,
        // while the empty-body shape below is the rare one.
        res.statusCode = 404;
        res.setHeader('content-type', 'text/html');
        res.end('<!DOCTYPE html><html><head><title>404: This page could not be found.</title></head><body>404</body></html>');
      } else if (req.url.includes('bare-404')) {
        // A 404 with NO error body: what a misconfigured origin returns, rather
        // than this API answering. Must not be reported as a malformed id.
        res.statusCode = 404;
        res.end('');
      } else {
        res.end(JSON.stringify({ success: true, id: 'stub-send-id', status: 'revoked' }));
      }
    } else {
      if (req.url.includes('html-404')) {
        res.statusCode = 404;
        res.setHeader('content-type', 'text/html');
        res.end('<!DOCTYPE html><html><head><title>404: This page could not be found.</title></head><body>404</body></html>');
        return;
      }
      if (req.url.includes('not-a-uuid')) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Send not found.' }));
        return;
      }
      res.end(JSON.stringify({
        id: 'stub-send-id', status: 'pending', deliveryMode: 'link', createdAt: 'x',
        expiresAt: 'y', downloadCount: 0, filesCount: 1,
        events: [{ action: 'api_send_created', createdAt: 'z' }],
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

{
  const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
  const info = client.getServerVersion();
  ok(info.version === pkg.version, `reported version ${info.version} equals package.json ${pkg.version}`);
}
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

  // Shape checks above cannot tell ciphertext from plaintext, nor a matching
  // key from an unrelated one. These three do, and they are the properties a
  // customer actually depends on.
  // base64url (as it travels in the fragment) back to the standard base64 the
  // package produces, so we can both decrypt with it and search the body for it.
  const keyB64 = Buffer.from(frag[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('base64');
  ok(
    !sent.raw.includes(keyB64) && !sent.raw.includes(frag[1]),
    'ZERO-KNOWLEDGE: the key appears NOWHERE in the raw request body, under any field name'
  );
  const ct = Buffer.from(sent.body.files[0].ciphertextBase64, 'base64');
  let plain = null;
  try {
    const ck = await crypto.subtle.importKey('raw', Buffer.from(keyB64, 'base64'), { name: 'AES-GCM' }, false, ['decrypt']);
    plain = Buffer.from(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ct.subarray(0, 12) }, ck, ct.subarray(12)));
  } catch { /* stays null -> assertion fails */ }
  ok(plain !== null && plain.equals(readFileSync(file)), 'the fragment key DECRYPTS the sent ciphertext back to the original file');
  ok(!ct.includes(Buffer.from('%PDF-1.4')), 'the payload on the wire is not plaintext');

  // The model's explicit inputs must actually reach the API.
  const withOpts = await client.callTool({
    name: 'secure_send',
    arguments: { filePath: file, deliveryMode: 'link', expiryHours: 3, message: 'for review' },
  });
  ok(!withOpts.isError, 'a call with explicit options succeeds');
  ok(requests.at(-1).body.expiryHours === 3, 'expiryHours is forwarded, not silently defaulted');
  ok(requests.at(-1).body.message === 'for review', 'message is forwarded');

  // fileBase64 happy path: previously only its validation errors ran.
  const b64 = await client.callTool({
    name: 'secure_send',
    arguments: { fileBase64: readFileSync(file).toString('base64'), filename: 'inline.pdf', mimeType: 'application/pdf', deliveryMode: 'link' },
  });
  ok(!b64.isError, 'fileBase64 mode succeeds');
  ok(requests.at(-1).body.files[0].filename === 'inline.pdf', 'and carries the given filename');
  ok(Buffer.from(requests.at(-1).body.files[0].ciphertextBase64, 'base64').length > 12, 'and real ciphertext');
}

console.log('size pre-flight');
{
  const big = join(dir, 'big.pdf');
  writeFileSync(big, Buffer.concat([Buffer.from('%PDF-1.4\n'), Buffer.alloc(11 * 1024 * 1024, 0x41)]));
  const before = requests.length;
  const res = await client.callTool({ name: 'secure_send', arguments: { filePath: big, deliveryMode: 'link' } });
  ok(res.isError === true, 'an oversized file is refused');
  ok(/3MB limit/.test(text(res)), "naming THIS tool's cap, not FileSeal's larger one");
  ok(!/10MB per-file limit/.test(text(res)), 'and not a cap the caller cannot actually use');
  ok(requests.length === before, 'WITHOUT encrypting and shipping a ~15MB body first');

  const mid = join(dir, 'mid.pdf');
  writeFileSync(mid, Buffer.concat([Buffer.from('%PDF-1.4\n'), Buffer.alloc(4 * 1024 * 1024, 0x42)]));
  const res2 = await client.callTool({ name: 'secure_send', arguments: { filePath: mid, deliveryMode: 'link' } });
  ok(res2.isError === true && /inline/.test(text(res2)), 'a 4MB file is refused for the same reason, with the same number');
  ok(requests.length === before, 'and also sends nothing');
}

console.log('email delivery failure');
{
  const res = await client.callTool({
    name: 'secure_send',
    arguments: { filePath: file, deliveryMode: 'email', recipientEmail: 'bounce@example.com' },
  });
  const out = text(res);
  ok(/could not email/i.test(out), 'a failed email is reported');
  ok(/receive\/stub-send-id/.test(out), 'and the claim link IS given — in email mode it works as-is');
  ok(!/resend/i.test(out) || /no resend tool/i.test(out), 'and no nonexistent resend tool is suggested');
}

console.log('recipientEmail in link mode');
{
  const res = await client.callTool({
    name: 'secure_send',
    arguments: { filePath: file, deliveryMode: 'link', recipientEmail: 'someone@example.com' },
  });
  ok(requests.at(-1).body.recipientEmail === undefined, 'link mode does not put the address on the wire at all');
  ok(!requests.at(-1).raw.includes('someone@example.com'), 'the address appears nowhere in the request body');
  ok(/no email was sent/i.test(text(res)), 'the result says plainly that no email was sent');
  ok(/ignored in link mode/i.test(text(res)), 'and that recipientEmail was ignored');
}

console.log('a rejected POST');
{
  const deny = join(dir, 'deny.pdf');
  writeFileSync(deny, '%PDF-1.4\ndenied\n%%EOF\n');
  const res = await client.callTool({ name: 'secure_send', arguments: { filePath: deny, deliveryMode: 'link' } });
  const out = text(res);
  ok(res.isError === true, 'a non-2xx POST is reported as an error');
  ok(/HTTP 402/.test(out), 'carrying the status');
  ok(/Upgrade required/.test(out), 'and the server message');
  ok(!/Share link/.test(out), 'and NO share link — the success path must not render on failure');
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

console.log('unknown extension');
{
  const weird = join(dir, 'thing.bin');
  writeFileSync(weird, 'data');
  const before = requests.length;
  const res = await client.callTool({ name: 'secure_send', arguments: { filePath: weird, deliveryMode: 'link' } });
  ok(res.isError === true && /could not infer mimeType/.test(text(res)), 'an unknown extension is refused, not guessed');
  ok(requests.length === before, 'and sends nothing');
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

  const status = await client.callTool({ name: 'send_status', arguments: { id: 'stub-send-id' } });
  const st = text(status);
  ok(/Status: pending/.test(st), 'send_status renders the status field, not another field');
  ok(/Delivery mode: link/.test(st), 'and the delivery mode');
  ok(/api_send_created/.test(st), 'and the audit events');
  const statusMissing = await client.callTool({ name: 'send_status', arguments: { id: 'not-a-uuid' } });
  ok(statusMissing.isError === true && /Send not found/.test(text(statusMissing)), 'send_status maps an API 404 to not-found');
  const statusHtml = await client.callTool({ name: 'send_status', arguments: { id: 'html-404' } });
  ok(statusHtml.isError === true, 'send_status errors on an HTML 404');
  ok(!/Send not found/.test(text(statusHtml)), 'and does NOT claim the send is missing when the endpoint is wrong');
  ok(/FILESEAL_API_BASE_URL/.test(text(statusHtml)), 'it points at the base URL, as revoke_send does');
  ok(!/<!DOCTYPE|<html/i.test(text(statusHtml)), 'and never pastes raw HTML into the model context');

  const twice = await client.callTool({ name: 'revoke_send', arguments: { id: 'stub-send-id' } });
  // NOT a test of idempotency: that is a server property, pinned by a test in
  // FileSeal's own (private) repo. All this shows is that the client reports a
  // 200 as success rather than inventing an error.
  ok(!twice.isError && /revoked/.test(text(twice)), 'a 200 from DELETE is reported as success, not an error');
  const collected = await client.callTool({ name: 'revoke_send', arguments: { id: 'collected-id' } });
  ok(collected.isError === true, '409 is reported as an error');
  // The realistic miss: a well-formed UUID that does not exist also 409s, so the
  // tool must NOT tell the model the document was collected.
  const gone = await client.callTool({ name: 'revoke_send', arguments: { id: '069b31db-461d-47e4-82c1-771f08fb0b95' } });
  ok(gone.isError === true, 'a well-formed unknown UUID is an error');
  ok(/does not exist/.test(text(gone)), "and the CLIENT's own wording admits the send may simply not exist");
  ok(
    /not created by this API key/.test(text(collected)),
    "even when the server sends its own 409 string, the CLIENT's wording is what reaches the model"
  );
  ok(
    !/^Send .* (has|was) .*collected/im.test(text(gone)),
    'and never states as FACT that the document was collected — a 409 cannot distinguish that from a missing send'
  );
  const malformed = await client.callTool({ name: 'revoke_send', arguments: { id: 'not-a-uuid' } });
  ok(malformed.isError === true && /not a valid send id/i.test(text(malformed)), '404 WITH an api error body is reported as a malformed id');
  ok(!/HTTP 404/.test(text(malformed)), 'and not as a raw HTTP error');
  const html = await client.callTool({ name: 'revoke_send', arguments: { id: 'html-404' } });
  ok(html.isError === true, 'an HTML 404 from a wrong base URL is an error');
  ok(!/not a valid send id/i.test(text(html)), 'and is NOT blamed on the id — this is the COMMON misconfiguration shape');
  ok(/FILESEAL_API_BASE_URL/.test(text(html)), 'it points at the base URL');
  ok(!/<!DOCTYPE|<html/i.test(text(html)), 'and never pastes the raw HTML page into the model context');
  ok(!/no error body/i.test(text(html)), 'and does not claim there was no body — an HTML page IS a body');

  const bare = await client.callTool({ name: 'revoke_send', arguments: { id: 'bare-404' } });
  ok(bare.isError === true, 'a bodyless 404 is still an error');
  ok(!/not a valid send id/i.test(text(bare)), 'but is NOT blamed on the id — that would misdirect the model');
  ok(/FILESEAL_API_BASE_URL/.test(text(bare)), 'it points at the base URL instead');
}

await client.close();
stub.close();
// The size cases write an 11MB and a 4MB file; the pre-push hook runs this on
// every push, so leaving the temp dir behind leaked ~15MB each time.
rmSync(dir, { recursive: true, force: true });
console.log(failures === 0 ? '\nSTUB E2E PASSED' : `\nSTUB E2E FAILED (${failures})`);
process.exit(failures === 0 ? 0 : 1);
