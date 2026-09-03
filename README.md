# fileseal-send (MCP server)

A standalone [Model Context Protocol](https://modelcontextprotocol.io) stdio
server that wraps the FileSeal **Secure Send API** (`/v1/sends`). It encrypts
files client-side (AES-GCM-256) before they ever reach FileSeal and exposes
three tools to an MCP client (e.g. Claude).

This package is self-contained: it does **not** import from the FileSeal Next
app. Its crypto (`crypto.mjs`) mirrors FileSeal's server-side attachment format
byte-for-byte — a 12-byte IV followed by AES-GCM ciphertext, with the key
base64url-encoded in the link fragment — so that ciphertext it produces
decrypts on the FileSeal `/receive/[id]` page. That format is pinned by a
round-trip test in the (private) FileSeal application repo, so treat any change
to `crypto.mjs` as a breaking change needing a version bump.

## Tools

- **`secure_send`** — encrypt a file and create a send.
  - Inputs: `filePath` *or* (`fileBase64` + `filename` + `mimeType`),
    `recipientEmail?`, `deliveryMode` (`'link'` default | `'email'`),
    `expiryHours?` (1-168, default 48), `message?`.
  - **link** mode (default, zero-knowledge): the AES key never leaves your
    machine; the tool returns the full share link with the key in its `#k=`
    fragment.
  - **email** mode: FileSeal emails the recipient a working link and stores the
    key server-side. Requires `recipientEmail`.
- **`send_status`** — `{ id }` → status, expiry, download count, audit events.
- **`revoke_send`** — `{ id }` → revoke the send and delete its blobs.

## Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `FILESEAL_API_KEY` | yes | — | Bearer token sent as `Authorization: Bearer <key>` on every call. The server exits at startup if unset. |
| `FILESEAL_API_BASE_URL` | no | `http://localhost:3000` | API origin. Routes are `<base>/v1/sends`. |

## Running

No install needed — `npx` fetches and runs the latest published version:

```bash
FILESEAL_API_KEY=fsk_... \
FILESEAL_API_BASE_URL=https://fileseal.uk \
npx -y @fileseal/send
```

The server speaks MCP over stdio, so it's normally launched by an MCP client
rather than run by hand.

<details>
<summary>Run from source</summary>

```bash
# from this package's directory
npm install
FILESEAL_API_KEY=fsk_... \
FILESEAL_API_BASE_URL=https://fileseal.uk \
node index.mjs
```
</details>

## Wiring into Claude (`.mcp.json`)

```json
{
  "mcpServers": {
    "fileseal-send": {
      "command": "npx",
      "args": ["-y", "@fileseal/send"],
      "env": {
        "FILESEAL_API_KEY": "fsk_your_api_key_here",
        "FILESEAL_API_BASE_URL": "https://fileseal.uk"
      }
    }
  }
}
```

The `"fileseal-send"` key is just the local server label; the npm package is
`@fileseal/send`. To run a local checkout instead, point `command`/`args` at
your copy of `index.mjs`.

## Discovery / MCP registry listing (GEO)

Copy for MCP registries and marketplaces. The literal name `fileseal-send` and the
one-line description are what assistants match against user intent, so keep them
stable and verb-first.

- **Name:** `fileseal-send`
- **npm package:** `@fileseal/send` (`npx -y @fileseal/send`)
- **One-line description:** Send a file to a person as a one-time, encrypted, auto-deleting download link.
- **Tags:** `file-sharing`, `secure`, `encryption`, `one-time`, `gdpr`, `file-delivery`, `email`
- **Tools:** `secure_send`, `send_status`, `revoke_send`
- **Homepage:** https://fileseal.uk/developers · **Docs:** https://fileseal.uk/developers/docs
- **Longer description:** Give an AI agent a tool to deliver a file to a human securely.
  Files are encrypted with AES-256; a one-click zero-knowledge mode keeps the key out of
  FileSeal. Each link works once, then the file is deleted, with an audit trail. UK-hosted, GDPR-ready.
