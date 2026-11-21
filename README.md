# TG ImageBed Pro (MVP)

A mobile-first Telegram-backed image library with Cloudflare Worker + D1 index.

## MVP features
- Upload up to 20 images per batch (20 MB/image limit; Telegram Bot API compatibility)
- Telegram stores the uploaded image as a document (preserves original file)
- D1-backed paginated library and filename search
- Immediate hide from gallery when deleting; Telegram delete failures are retried by scheduled task
- Image proxy endpoint `/i/:id`, Cloudflare cache headers
- Mobile responsive UI; copy direct image URL; select/bulk delete

## Deploy
1. Create a Telegram bot with BotFather. Keep the token private.
2. Create a private Telegram channel for storage; add the bot as administrator with permission to post/delete messages. Obtain the channel ID (usually `-100...`).
3. Create a Cloudflare D1 database named `tg-imagebed-pro`, run `schema.sql` in its console.
4. Replace `database_id` in `wrangler.toml` with the D1 ID.
5. Deploy with Wrangler (or connect the GitHub repo in Cloudflare Workers & Pages and deploy).
6. Open the site once and set the admin password on the first-run screen (stored as a PBKDF2 hash in D1; sessions last 7 days). No dashboard step needed.
   Optional override: setting the `ADMIN_TOKEN` variable/secret also works as the admin password, and skips the first-run screen.
7. In Settings → Telegram, bind the bot: create a bot with BotFather, create a private channel, add the bot as administrator, and paste the bot token + channel ID (`-100...`). The site verifies the token and the bot's admin status before saving.
   Alternative: set `TG_BOT_TOKEN` / `TG_CHAT_ID` as Worker secrets instead; when set, they take precedence and the settings form is disabled.

CLI commands:
```bash
npm install -g wrangler
wrangler login
wrangler d1 create tg-imagebed-pro
# copy database_id to wrangler.toml
wrangler d1 execute tg-imagebed-pro --remote --file=schema.sql
wrangler deploy
# open the site once, set the admin password, then bind the bot in Settings → Telegram
```

For static assets, Wrangler will upload `public/` under the Assets binding.

## Important limitations / notes
- Telegram is the storage backend; it is not an independent backup. Keep a second copy of irreplaceable images.
- Bot API limits and Telegram availability can change. MVP restricts image uploads to 20 MB to stay within conservative limits.
- D1 stores metadata and Telegram identifiers, not image bytes.
- Cache invalidation on delete is best-effort; the gallery record disappears immediately. Previously cached content may remain briefly at edge locations or in a browser cache.
- The project uses an admin bearer secret. Do not share it or commit secrets to GitHub.
- Before production use, consider adding rate limits, audit logs, token rotation, upload concurrency control, and an optional custom-domain cache purge integration.
