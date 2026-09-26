# fileseal-send (MCP server)

A standalone [Model Context Protocol](https://modelcontextprotocol.io) stdio
server that wraps the FileSeal **Secure Send API** (`/v1/sends`). It encrypts
files client-side (AES-GCM-256) before they ever reach FileSeal and exposes
three tools to an MCP client (e.g. Claude).

This package is self-contained: it does **not** import from the FileSeal Next
app. Its crypto (`crypto.mjs`) mirrors FileSeal's server-side attachment format
byte-for-byte (a 12-byte IV followed by AES-GCM ciphertext, with the key
base64url-encoded in the link fragment), so that ciphertext it produces
decrypts on the FileSeal `/receive/[id]` page. That page fixes the format: a
changed `crypto.mjs` produces links that will not open.

## Tools

- **`secure_send`**: encrypt one or more files and create a send.
  - Inputs: `filePath`, *or* `filePaths` (up to 10 files under one link),
    *or* (`fileBase64` + `filename` + `mimeType`),
    `recipientEmail?`, `deliveryMode` (`'link'` default | `'email'`),
    `expiryHours?` (1-168, default 48), `message?`, `senderName?`.
  - **link** mode (default, zero-knowledge for the file): the AES key is never
    sent to FileSeal; the tool returns the full share link with the key in its
    `#k=` fragment.
  - **email** mode: FileSeal emails the recipient a working link and stores the
    key server-side. Requires `recipientEmail`. Pass `senderName` too: without
    it the email says the files are from "Someone".
  - **Not encrypted, in either mode:** the file name, `senderName` and
    `message`. FileSeal stores them as plain text and anyone with the link can
    read them, so keep secrets out of `message`.
  - **Several files:** pass them together as `filePaths` to send them under
    one link. Calling once per file makes a separate link for each.
  - **Limits:** up to 10 files per call, 3 MB in total. The files travel inline
    as base64 in the request body, which is what caps it; FileSeal's own 10 MB
    per file is not reachable through this tool. Types: PDF, DOC, DOCX, TXT,
    JPG, PNG.
- **`send_status`**: `{ id }` → status, expiry, download count, audit events.
  Only sends created with the same API key are visible.
- **`revoke_send`**: `{ id }` → the link stops working immediately, and
  FileSeal attempts to delete the encrypted files from its servers.

## Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `FILESEAL_API_KEY` | yes | none | Bearer token sent as `Authorization: Bearer <key>` on every call. The server exits at startup if unset. |
| `FILESEAL_API_BASE_URL` | no | `https://fileseal.uk` | API origin. Change it only to point at another FileSeal instance, such as `http://localhost:3000` when developing FileSeal itself. Routes are `<base>/v1/sends`. Versions before 0.1.3 defaulted to `http://localhost:3000`, so set it explicitly if you pin an older version. |

## Running

No install needed: `npx` fetches and runs the latest published version:

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

## As a Claude Code plugin

The [`claude-plugin/`](claude-plugin/) folder packages this server as a Claude
Code plugin, with a skill that tells Claude how to use it. The plugin asks for
your API key when you enable it and keeps it in secure storage rather than in
your settings files. To install it from this repository:

```text
/plugin marketplace add fileseal/mcp-send
/plugin install fileseal@fileseal
```

It works in Claude Code only. The [plugin's README](claude-plugin/README.md)
explains why, and lists what it runs and sends.
