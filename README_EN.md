# fuClaudeBackend

English | 中文: `README.md`

## Overview
This is a lightweight backend proxy + Key management admin panel based on the open-source fuclaude. It is an enhanced management version mainly for the "Shihuang" use case and follows ideas from community discussions.

## Features
- Guest / site login
- Admin panel: user and Key management
- Account chooser page (with status display)
- Key expiry support (expired keys are hidden)

## Quick start
1) Copy `config.example.json` to `config.json`
2) (Optional) Copy `data.example.json` to `data.json` (or let it be created on first save)
3) Run `node sever.js`
4) Open `http://localhost:3000`

## Configuration (config.json)
- `ORIGINAL_WEBSITE`: upstream site address (recommended to self-host)
- `SESSION_KEYS`: list of `{ id, label, value, expiresAt }`
- `DEFAULT_KEY_ID`: default Key ID
- `SESSION_KEY`: legacy single Key (optional)
- `SITE_PASSWORD` / `GUEST_PASSWORD`: login passwords
- `PORT`: server port

## Data file (data.json)
- `keys`: same structure as `SESSION_KEYS` (`value` is secret)
- `defaultKeyId`
- `users`: `{ username, active, isolated, keys, createdAt, lastLoginAt, expiresAt }`

## Key expiry
- `expiresAt` accepts any string supported by `Date.parse()` (ISO 8601 recommended)
- You can input it manually in the admin panel
- If empty, it defaults to 27 days after creation
- Expired Keys are hidden on `/choose`

## References
- fuclaude project: https://github.com/wozulong/fuclaude
- Community discussion: https://linux.do/t/topic/131611
- Idea reference: https://linux.do/t/topic/131757
- Community user: https://linux.do/u/neo
