---
name: secure-send
description: Use when the user asks to send a file through FileSeal or as a one-time encrypted download link, or to check on or revoke a FileSeal send. Covers choosing link or email delivery, what FileSeal can read, and the size and type limits.
---

# Sending files with FileSeal

The tools are `secure_send`, `send_status` and `revoke_send`.

## Before calling secure_send

Confirm these with the user unless they have already said them:

1. **The files.** Pass one file as `filePath`, or several as `filePaths` so they arrive under one link, using absolute paths. Calling once per file makes a separate link for each. Avoid `fileBase64` for anything but a very small file, because it means writing the whole file out as base64 inside the tool call.
2. **The recipient.**
3. **The delivery mode.** It decides who holds the decryption key, so do not pick it silently.
   - `link` (the default): the key is never sent to FileSeal. The tool returns a link carrying the key after `#k=`, and the user passes that link to the recipient. `recipientEmail` is ignored and no email is sent.
   - `email`: FileSeal emails the recipient a working link, so FileSeal stores the key on its servers. It needs `recipientEmail`. Pass `senderName` too, as the name the recipient will recognise: without it the email says the file is from "Someone", and the email warns recipients about links from senders they do not recognise.

Check the limits before calling rather than letting the call fail: up to 10 files per call, 3MB in total, and only PDF, DOC, DOCX, TXT, JPG or PNG. If the files together are over 3MB, send them in smaller groups, each of which gets its own link. For a single file over 3MB, say that this tool cannot send it. A PDF, DOC, DOCX, JPG or PNG of up to 10MB can be sent from the FileSeal dashboard instead; the dashboard does not accept TXT files.

`expiryHours` runs from 1 to 168. The default is 48.

## What is not encrypted

In both modes FileSeal stores the file name, `senderName` and `message` as plain text, and anyone with the link can read them. Never put a password, account number or other secret in `message`. If a file name itself gives something away, pass a neutral `filename` that keeps the same extension, because the extension sets the file type. `filename` works only with `filePath`, so rename such a file before sending it with others.

## After sending

- Give the user the send ID. They need it to check or revoke the send later.
- In link mode, give the full link exactly as returned, including everything after `#k=`: without that part the file cannot be decrypted. Point out that the link is also in this conversation.
- In email mode, say whether the email was sent. If it was not, the tool returns a link the user can pass on themselves.
- If the call fails with a server error, do not retry on your own. The tool reports that the send may still have been created, and a retry could create a second live link to the file. Tell the user instead.

## Checking and revoking

- `send_status` takes a send ID and reports the status, expiry, download count and events. It only sees sends made with the same API key.
- `revoke_send` cannot be undone, so confirm with the user first. The link stops working at once and FileSeal attempts to delete the encrypted files from its servers. A send that has already been collected cannot be revoked.
