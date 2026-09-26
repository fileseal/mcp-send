# FileSeal for Claude Code

Send a file to a person as a one-time, encrypted, auto-deleting download link,
then check whether it has been downloaded or revoke it, without leaving Claude
Code. The plugin runs the FileSeal Secure Send MCP server
([`@fileseal/send`](https://www.npmjs.com/package/@fileseal/send)) on your
computer, and adds a skill that tells Claude how to use it: which delivery mode
to choose, what FileSeal can read, and the limits.

## What you need

- A FileSeal account and an API key. Create the key in FileSeal under
  **Settings, Developer Tools, API keys**. Claude Code asks for it when you
  enable the plugin and keeps it in secure storage rather than in
  `settings.json`. To change it later, run
  `/plugin configure fileseal@fileseal`.
- Node.js 20 or newer, because the server runs through `npx`.
- Sends use your FileSeal plan. On a trial, each send uses one of the same
  trial seals as the FileSeal dashboard.

## Where it works

In Claude Code only: the terminal, the IDE extensions and the desktop app's
Code tab. Claude chat does not run MCP servers that start on your computer, and
Cowork does not ask for the API key that this server needs, so neither loads
it.

## Tools

- **`secure_send`** encrypts one or more files (up to 10, under one link) and
  creates a send, in `link` mode (the default) or `email` mode.
- **`send_status`** reports a send's status, expiry, download count and events.
- **`revoke_send`** stops a send's link working and asks FileSeal to delete the
  encrypted files.

## What the plugin runs and sends

- It runs the published `@fileseal/send` package with `npx`, pinned to the
  exact version in `.claude-plugin/plugin.json`. `npx` downloads that package
  and its dependencies from the npm registry.
- The file is encrypted on your computer (AES-GCM-256) before it is uploaded,
  and the server sends it only to `https://fileseal.uk`. It contacts no other
  host and sends no telemetry.
- In `link` mode the decryption key is never sent to FileSeal. It is in the
  `#k=` part of the link the tool returns, so it appears in your conversation
  with Claude.
- In `email` mode FileSeal stores the key on its servers so that it can email
  the recipient a working link, and the recipient's address is sent to
  FileSeal.
- In both modes FileSeal stores the file name, your sender name and any message
  as plain text, and anyone with the link can read them.

## Limits

Up to 10 files per send, 3MB in total, as PDF, DOC, DOCX, TXT, JPG or PNG. The
files travel inside the API request, which is what sets the 3MB ceiling. Expiry is 1
to 168 hours, 48 by default. For a larger PDF, DOC, DOCX, JPG or PNG, the
FileSeal dashboard accepts files up to 10MB. It does not accept TXT.

## Examples

- "Send `~/Documents/engagement-letter.pdf` to my client as a FileSeal link
  that expires in 24 hours."
- "Email `invoice-0142.pdf` to jane@example.com through FileSeal, from Smith
  and Co Accountants."
- "Has that FileSeal send been downloaded yet? If not, revoke it."

## Privacy policy and support

FileSeal's privacy policy is at <https://fileseal.uk/privacy>. It covers what
FileSeal collects, how it is used and stored, who it is shared with, and how
long it is kept. For help, email <support@fileseal.uk>.

## License

MIT. The server's source is in this repository.
