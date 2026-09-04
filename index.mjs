#!/usr/bin/env node
/**
 * fileseal-send — a standalone MCP stdio server that wraps the FileSeal
 * authenticated Secure Send API (`POST/GET/DELETE /v1/sends`).
 *
 * Standalone package: does NOT import from the FileSeal app. Crypto is mirrored
 * locally in ./crypto.mjs, matching FileSeal's server-side attachment format.
 *
 * Env:
 *   FILESEAL_API_KEY       (required) — Bearer token for the /v1 API.
 *   FILESEAL_API_BASE_URL  (default 'http://localhost:3000') — API origin.
 *                          NOTE: routes live under <base>/v1/sends.
 */

import { readFile } from 'node:fs/promises';
import { basename, extname } from 'node:path';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import {
  generateSealKey,
  encryptToAttachmentFormat,
  keyToFragment,
} from './crypto.mjs';

const API_KEY = process.env.FILESEAL_API_KEY;
const BASE_URL = (process.env.FILESEAL_API_BASE_URL ?? 'http://localhost:3000').replace(
  /\/+$/,
  ''
);
// Canonical public path is /v1/sends (a next.config rewrite maps it to the
// App Router handlers under /api/v1/sends; both paths work).
const SENDS_URL = `${BASE_URL}/v1/sends`;

if (!API_KEY) {
  process.stderr.write(
    'fileseal-send: FILESEAL_API_KEY is required but not set. Exiting.\n'
  );
  process.exit(1);
}

// `engines.node` is ADVISORY: npm only warns unless engine-strict is set, and
// `npx -y` does not enforce it at all. Without this check, an unsupported
// runtime produced the worst possible shape — the server started, advertised
// all three tools, and threw only on the first secure_send, because
// globalThis.crypto sat behind a flag until Node 19. Fail at startup instead.
if (!globalThis.crypto?.subtle) {
  process.stderr.write(
    `fileseal-send: this runtime has no Web Crypto (globalThis.crypto.subtle). ` +
      `Node 20 or newer is required; this is ${process.version}. Exiting.\n`
  );
  process.exit(1);
}

// Mirrors MAX_FILE_BYTES in src/app/api/v1/sends/route.ts. INLINE_SAFE_BYTES is
// the practical ceiling for THIS transport: bytes travel inline as base64
// (~1.37x with the IV and tag), against a ~4.5MB request body limit.
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const INLINE_SAFE_BYTES = 3 * 1024 * 1024;

// Minimal extension -> MIME inference for the API allowlist.
const MIME_BY_EXT = {
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx':
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.txt': 'text/plain',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
};

function inferMimeType(filename) {
  return MIME_BY_EXT[extname(filename).toLowerCase()] ?? undefined;
}

function textResult(text, isError = false) {
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) };
}

/**
 * Base64-encode a Uint8Array (Node Buffer is fine in this standalone runtime).
 */
function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Common headers for every API call.
 */
function apiHeaders() {
  return {
    Authorization: `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
  };
}

/**
 * Read a JSON body defensively; on non-JSON return a synthetic shape.
 */
async function readJson(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: text.slice(0, 500) };
  }
}

// Version is read from package.json rather than duplicated here: a hardcoded
// copy silently drifts from the published version, and the version an MCP
// client reports back is the only clue to which build a user is running.
// Guarded: the version is cosmetic, so a missing or unreadable package.json
// must not stop the server booting. npm always packs package.json, so the
// published path is safe — but the README invites pointing an MCP client at a
// vendored copy of index.mjs + crypto.mjs, and that copy may not have it.
const PACKAGE_VERSION = await readFile(new URL('./package.json', import.meta.url), 'utf8')
  .then((raw) => JSON.parse(raw).version ?? 'unknown')
  .catch(() => 'unknown');

const server = new McpServer({
  name: 'fileseal-send',
  version: PACKAGE_VERSION,
});

// ---------------------------------------------------------------------------
// secure_send
// ---------------------------------------------------------------------------
server.registerTool(
  'secure_send',
  {
    title: 'Secure send a file via FileSeal',
    description:
      'Send a file to a person as a one-time, encrypted, auto-deleting download link. ' +
      'Use when you need to deliver a file to a human securely, or want the link to expire ' +
      'after a single download. Encrypts the file client-side (AES-GCM-256) and creates a ' +
      'FileSeal secure send. In "link" mode (default, zero-knowledge) the key never leaves ' +
      'this machine and is returned only inside the share link fragment. In "email" mode ' +
      'FileSeal emails the recipient a working link and stores the key server-side. ' +
      'Limits: 10MB per file and 50MB per send; accepted types are PDF, DOC, DOCX, TXT, ' +
      'JPG and PNG. Files are sent inline, so anything over about 3MB of plaintext may ' +
      'exceed the request body limit even though it is under the 10MB cap.',
    inputSchema: {
      filePath: z
        .string()
        .optional()
        .describe('Absolute or relative path to the file to send.'),
      fileBase64: z
        .string()
        .optional()
        .describe('Base64-encoded file bytes (alternative to filePath; requires filename & mimeType).'),
      filename: z.string().optional().describe('Filename; inferred from filePath if omitted.'),
      mimeType: z
        .string()
        .optional()
        .describe('MIME type; inferred from the file extension if omitted.'),
      recipientEmail: z
        .string()
        .email()
        .optional()
        .describe(
          'Recipient email — REQUIRED when deliveryMode is "email". IGNORED in "link" mode: ' +
            'no email is sent and the address is not stored, so you must share the link yourself.'
        ),
      deliveryMode: z
        .enum(['link', 'email'])
        .default('link')
        .describe('"link" (zero-knowledge, default) or "email".'),
      expiryHours: z
        .number()
        .min(1)
        .max(168)
        .default(48)
        .describe('Hours until the send expires (1-168, default 48).'),
      message: z
        .string()
        .max(1000)
        .optional()
        .describe('Optional message to the recipient.'),
    },
  },
  async (args) => {
    const {
      filePath,
      fileBase64,
      filename,
      mimeType,
      recipientEmail,
      deliveryMode = 'link',
      expiryHours = 48,
      message,
    } = args;

    // 1. Resolve bytes + filename + mimeType.
    let bytes;
    let resolvedFilename = filename;
    let resolvedMimeType = mimeType;

    try {
      if (filePath) {
        const buf = await readFile(filePath);
        bytes = new Uint8Array(buf);
        if (!resolvedFilename) resolvedFilename = basename(filePath);
        if (!resolvedMimeType) resolvedMimeType = inferMimeType(resolvedFilename);
      } else if (fileBase64) {
        if (!filename || !mimeType) {
          return textResult(
            'Error: when using fileBase64 you must also provide filename and mimeType.',
            true
          );
        }
        bytes = new Uint8Array(Buffer.from(fileBase64, 'base64'));
      } else {
        return textResult('Error: provide either filePath or fileBase64.', true);
      }
    } catch (err) {
      return textResult(
        `Error reading file: ${err instanceof Error ? err.message : String(err)}`,
        true
      );
    }

    if (!bytes || bytes.length === 0) {
      return textResult('Error: the file is empty or could not be read.', true);
    }
    // Pre-flight the size the API will enforce, so an oversized file fails here
    // instead of after encrypting and shipping a base64-inflated body — an 11MB
    // file previously produced a ~14.7MB POST before the server rejected it,
    // and the model was shown the platform's raw non-JSON 413 page.
    if (bytes.length > MAX_FILE_BYTES) {
      return textResult(
        `Error: ${resolvedFilename ?? 'the file'} is ${(bytes.length / 1024 / 1024).toFixed(1)}MB, ` +
          `over FileSeal's ${MAX_FILE_BYTES / 1024 / 1024}MB per-file limit.`,
        true
      );
    }
    if (bytes.length > INLINE_SAFE_BYTES) {
      return textResult(
        `Error: ${resolvedFilename ?? 'the file'} is ${(bytes.length / 1024 / 1024).toFixed(1)}MB. ` +
          `This tool sends file bytes inline as base64, which inflates them by about a third, so ` +
          `anything over ~${(INLINE_SAFE_BYTES / 1024 / 1024).toFixed(0)}MB exceeds the API's request body limit. ` +
          `Send a smaller file.`,
        true
      );
    }
    if (!resolvedMimeType) {
      return textResult(
        'Error: could not infer mimeType — please pass mimeType explicitly.',
        true
      );
    }
    if (deliveryMode === 'email' && !recipientEmail) {
      return textResult(
        'Error: recipientEmail is required when deliveryMode is "email".',
        true
      );
    }

    // 2. Generate key + encrypt to the attachment format.
    let key;
    let ciphertextBase64;
    try {
      key = await generateSealKey();
      const ciphertext = await encryptToAttachmentFormat(bytes, key);
      ciphertextBase64 = bytesToBase64(ciphertext);
    } catch (err) {
      return textResult(
        `Error encrypting file: ${err instanceof Error ? err.message : String(err)}`,
        true
      );
    }

    // 3. Build the request body matching POST /v1/sends.
    const file = {
      filename: resolvedFilename,
      mimeType: resolvedMimeType,
      fileSize: bytes.length,
      ciphertextBase64,
      // zk invariant: encryptionKey ONLY in email mode (its presence is a 400 in link mode).
      ...(deliveryMode === 'email' ? { encryptionKey: key } : {}),
    };

    const body = {
      deliveryMode,
      expiryHours,
      files: [file],
      ...(message ? { message } : {}),
      ...(recipientEmail ? { recipientEmail } : {}),
    };

    // 4. POST.
    let response;
    try {
      response = await fetch(SENDS_URL, {
        method: 'POST',
        headers: apiHeaders(),
        body: JSON.stringify(body),
      });
    } catch (err) {
      return textResult(
        `Error calling FileSeal API: ${err instanceof Error ? err.message : String(err)}`,
        true
      );
    }

    const data = await readJson(response);
    if (!response.ok || !data.success) {
      return textResult(
        `FileSeal API error (HTTP ${response.status}): ${data.error ?? 'Unknown error'}`,
        true
      );
    }

    // 5. Format the result.
    if (deliveryMode === 'link') {
      // The key never went to the server; assemble the full share link locally.
      const shareLink = `${data.claimUrl}#k=${keyToFragment(key)}`;
      return textResult(
        [
          'Secure send created (link / zero-knowledge mode).',
          `Send ID: ${data.id}`,
          `Share link: ${shareLink}`,
          `Expires: ${data.expiresAt}`,
          `Files: ${data.filesCount}, total size: ${data.totalSize} bytes`,
          '',
          'The decryption key lives ONLY in the #k= fragment of the link above — ',
          'FileSeal never received it. Share the full link with your recipient.',
          ...(recipientEmail
            ? [
                '',
                `NOTE: no email was sent. recipientEmail (${recipientEmail}) is ignored in link mode; ` +
                  `use deliveryMode "email" if you want FileSeal to deliver it.`,
              ]
            : []),
        ].join('\n')
      );
    }

    return textResult(
      [
        'Secure send created (email mode).',
        `Send ID: ${data.id}`,
        `Email sent: ${data.emailSent ? 'yes' : 'no'}`,
        `Recipient: ${recipientEmail}`,
        `Expires: ${data.expiresAt}`,
        `Files: ${data.filesCount}, total size: ${data.totalSize} bytes`,
        data.emailSent
          ? ''
          : `\nFileSeal could not email the recipient. There is no resend tool — but in email ` +
            `mode the key is stored server-side, so this link works as-is and you can pass it ` +
            `to them yourself:\n${data.claimUrl}`,
      ].join('\n')
    );
  }
);

// ---------------------------------------------------------------------------
// send_status
// ---------------------------------------------------------------------------
server.registerTool(
  'send_status',
  {
    title: 'Check a FileSeal send status',
    description: 'Fetch the status, expiry, download count and audit events for a send by id.',
    inputSchema: {
      id: z.string().describe('The send id returned by secure_send.'),
    },
  },
  async ({ id }) => {
    let response;
    try {
      response = await fetch(`${SENDS_URL}/${encodeURIComponent(id)}`, {
        method: 'GET',
        headers: apiHeaders(),
      });
    } catch (err) {
      return textResult(
        `Error calling FileSeal API: ${err instanceof Error ? err.message : String(err)}`,
        true
      );
    }

    const data = await readJson(response);
    if (response.status === 404) {
      return textResult(`Send not found: ${id}`, true);
    }
    if (!response.ok) {
      return textResult(
        `FileSeal API error (HTTP ${response.status}): ${data.error ?? 'Unknown error'}`,
        true
      );
    }

    const events = Array.isArray(data.events) ? data.events : [];
    const eventLines =
      events.length > 0
        ? events.map((e) => `  - ${e.action} @ ${e.createdAt}`).join('\n')
        : '  (no events)';

    return textResult(
      [
        `Send ${data.id}`,
        `Status: ${data.status}`,
        `Delivery mode: ${data.deliveryMode}`,
        ...(data.recipientEmail ? [`Recipient: ${data.recipientEmail}`] : []),
        `Created: ${data.createdAt}`,
        `Expires: ${data.expiresAt}`,
        `Download expires: ${data.downloadExpiresAt ?? 'n/a'}`,
        `Download count: ${data.downloadCount}`,
        `Files: ${data.filesCount}`,
        'Events:',
        eventLines,
      ].join('\n')
    );
  }
);

// ---------------------------------------------------------------------------
// revoke_send
// ---------------------------------------------------------------------------
server.registerTool(
  'revoke_send',
  {
    title: 'Revoke a FileSeal send',
    description:
      'Revoke a send by id, deleting its encrypted blobs. Idempotent: revoking a send ' +
      'this key already revoked succeeds. Returns an error (409) if the send has been ' +
      'collected, does not exist, or was created by a different API key — the API does ' +
      'not distinguish these. A malformed id returns 404.',
    inputSchema: {
      id: z.string().describe('The send id to revoke.'),
    },
  },
  async ({ id }) => {
    let response;
    try {
      response = await fetch(`${SENDS_URL}/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: apiHeaders(),
      });
    } catch (err) {
      return textResult(
        `Error calling FileSeal API: ${err instanceof Error ? err.message : String(err)}`,
        true
      );
    }

    const data = await readJson(response);
    // Measured against production 2026-09-03. DELETE is NOT symmetric with GET:
    //   200 - revoked, including re-revoking one this key already revoked
    //         (the route's UPDATE excludes only 'collected', so 'cancelled' matches)
    //   409 - collected, OR a well-formed id that does not exist, OR another
    //         key's send. The route cannot tell these apart, so neither can we.
    //   404 - ONLY a malformed id (isValidUUID uses a strict v1-5 regex).
    // An earlier version of this comment claimed an unknown id returns 404 and
    // narrowed the 409 text to "already collected". That was wrong, and it made
    // the tool tell the model that a send which never existed had been
    // COLLECTED - i.e. that someone downloaded a document. Do not narrow it
    // again: the mistake came from spot-checking with the all-zeros UUID, which
    // fails isValidUUID and so 404s for the wrong reason.
    // A 404 from THIS route means a malformed id — but a 404 can also come from
    // a misconfigured origin (the default base URL is localhost, and a base URL
    // with a path prefix, or a dev server without the /v1/sends rewrite, 404s
    // the whole route). Only claim the id is invalid when the response actually
    // looks like this API answering; otherwise say so, because "your id is
    // malformed" sends a model looking in the wrong place entirely.
    if (response.status === 404) {
      if (typeof data.error === 'string' && data.error.length > 0) {
        return textResult(`Not a valid send id: ${id}`, true);
      }
      return textResult(
        `FileSeal API returned 404 with no error body for ${SENDS_URL}/${encodeURIComponent(id)} — ` +
          `check FILESEAL_API_BASE_URL (currently ${BASE_URL}).`,
        true
      );
    }
    if (response.status === 409) {
      // Do NOT lead with data.error. The route always sends JSON on 409, so
      // `data.error ?? <local>` made the corrected wording dead code — and the
      // server's own string says "already revoked", which is FALSE (a re-revoke
      // returns 200) and omits the other-API-key case. The model would read
      // "already revoked" and conclude revocation was in effect when the send
      // may have been collected, i.e. downloaded by the recipient.
      const detail = typeof data.error === 'string' && data.error.length > 0 ? ` (API said: ${data.error})` : '';
      return textResult(
        `Could not revoke ${id}: it has already been collected, does not exist, or was not created by this API key.${detail}`,
        true
      );
    }
    if (!response.ok || !data.success) {
      return textResult(
        `FileSeal API error (HTTP ${response.status}): ${data.error ?? 'Unknown error'}`,
        true
      );
    }

    return textResult(`Send ${data.id} revoked. Status: ${data.status}.`);
  }
);

// ---------------------------------------------------------------------------
// Boot.
// ---------------------------------------------------------------------------
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write('fileseal-send MCP server running on stdio.\n');
}

main().catch((err) => {
  process.stderr.write(
    `fileseal-send fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`
  );
  process.exit(1);
});
