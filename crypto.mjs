/**
 * Crypto helpers for the fileseal-send MCP server.
 *
 * SOURCE OF TRUTH: ../../src/lib/attachments.ts in the FileSeal Next app.
 * This file MUST byte-for-byte mirror that module's encryption format so that
 * ciphertext produced here decrypts cleanly via its `decryptAttachment` on the
 * `/receive/[id]` page. Specifically:
 *   - keys are raw AES-256-GCM keys, base64-encoded (btoa) — `generateAttachmentKey`
 *   - the on-the-wire blob format is EXACTLY [12-byte IV][AES-GCM ciphertext]
 *     (decryptAttachment does `slice(0,12)` for the IV, `slice(12)` for the body)
 *   - the URL fragment uses the base64url alphabet with padding stripped —
 *     `keyToFragment` / `fragmentToKey`
 *
 * Standalone by design: this package does NOT import from the Next app (no `@/`
 * alias). It relies only on globals available in Node 22 (crypto.subtle, btoa,
 * atob), exactly as the isomorphic source module does.
 */

/**
 * Generate a base64-encoded raw AES-256-GCM key.
 * Mirrors attachments.ts `generateAttachmentKey`.
 */
export async function generateSealKey() {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const exportedKey = await crypto.subtle.exportKey('raw', key);
  const keyArray = new Uint8Array(exportedKey);

  // Chunked base64 to match the source module (and avoid stack overflow on
  // large inputs — irrelevant for a 32-byte key but kept for parity).
  let binary = '';
  const chunkSize = 1024;
  for (let i = 0; i < keyArray.length; i += chunkSize) {
    const chunk = keyArray.slice(i, i + chunkSize);
    for (let j = 0; j < chunk.length; j++) {
      binary += String.fromCharCode(chunk[j]);
    }
  }

  return btoa(binary);
}

/**
 * Encrypt raw bytes into the EXACT [12-byte IV][AES-GCM ciphertext] format that
 * attachments.ts `encryptAttachment` produces and `decryptAttachment` consumes.
 *
 * @param {Uint8Array} bytes - plaintext file bytes
 * @param {string} base64Key - base64-encoded raw AES-256 key (from generateSealKey)
 * @returns {Promise<Uint8Array>} IV-prefixed ciphertext
 */
export async function encryptToAttachmentFormat(bytes, base64Key) {
  // Import the key from base64 (mirrors atob -> charCodeAt decode).
  const keyData = new Uint8Array(
    atob(base64Key)
      .split('')
      .map((char) => char.charCodeAt(0))
  );

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  // 12-byte IV — must match decryptAttachment's slice(0, 12).
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    bytes
  );

  // Combine IV + ciphertext into a single buffer: [IV(12)][ciphertext].
  const result = new Uint8Array(iv.length + encrypted.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(encrypted), iv.length);

  return result;
}

/**
 * Encode a standard base64 key for safe use in a URL fragment (#k=...).
 * Mirrors attachments.ts `keyToFragment`: base64url alphabet, padding stripped.
 */
export function keyToFragment(base64Key) {
  return base64Key.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
