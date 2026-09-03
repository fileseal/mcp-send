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
      'FileSeal emails the recipient a working link and stores the key server-side.',
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
        .describe('Recipient email — REQUIRED when deliveryMode is "email".'),
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
          : '\nWarning: FileSeal could not send the email — check the recipient and try revoking/resending.',
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
      'Revoke a send by id, deleting its encrypted blobs. Idempotent: revoking an ' +
      'already-revoked send succeeds. Fails if the send has already been collected ' +
      '(409) or does not exist (404).',
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
    // Verified against production 2026-09-03: already-revoked returns 200
    // (idempotent), already-collected returns 409, an unknown id returns 404.
    // This branch used to claim all three were 409, and there was no 404 case
    // even though send_status has one.
    if (response.status === 404) {
      return textResult(`Send not found: ${id}`, true);
    }
    if (response.status === 409) {
      return textResult(
        `Could not revoke ${id}: ${data.error ?? 'it has already been collected.'}`,
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
