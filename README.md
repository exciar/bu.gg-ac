# Anti-Cheat

A Discord verification bot for **BU.gg (Bicol University Gaming Guild)**. A member runs `/verify`, signs in with their
`@bicol-u.edu.ph` Google account, and gets the verified role but only if Google says the
address is verified, it belongs to the Bicol University domain, and it appears on the roster
the officers maintain.

One school email links to exactly one Discord account.

**What gets stored:** the member's school email, the name on their Google account, their
Discord user ID, and the time they verified. Nothing else. `/unverify` deletes it immediately.

---

## How it works

```
/verify  ──►  ephemeral message with a button
                 │
                 ▼
         BASE_URL/login?state=…      signed, 10-minute link
                 │                    consent notice shown here
                 ▼
         Google sign-in (hd hint = bicol-u.edu.ph)
                 │
                 ▼
         BASE_URL/callback           verify ID token → check email_verified,
                 │                   hd, roster, one-account rule
                 ▼
         role assigned + link stored
```

The `hd=bicol-u.edu.ph` parameter on the Google URL is only a hint that pre-selects the school
account picker. The real domain check happens server-side against the `hd` claim in the signed
ID token, so it cannot be bypassed by editing the URL.

---

## Commands

| Command | Who | What it does |
|---|---|---|
| `/verify` | anyone | Ephemeral message with a personal 10-minute verification link |
| `/unverify` | anyone | Deletes your stored email and removes your verified role |
| `/ac lookup @user` | officers | Shows the name and email linked to a member |
| `/ac list` | officers | Every verified member as a CSV: name, Discord username, nickname, email, timestamp |
| `/ac revoke @user` | officers | Deletes a member's link and removes their role |
| `/ac reload-roster` | officers | Re-reads the roster CSV from disk |
| `/ac stats` | officers | Verified count, roster size, attempts by outcome |
| `/ac enforce status` | officers | Who is on the kick clock and when they are due |
| `/ac enforce start` | officers | Puts every member who joins from now on under a deadline |
| `/ac enforce stop` | officers | Stops the clock; nobody is kicked |

`/ac` commands require one of the officer roles in `ADMIN_ROLE_IDS`. Every reply is ephemeral.

---

## 1. Google Cloud setup

Google moved these settings out of "APIs & Services → OAuth consent screen" and into
**Google Auth Platform**, split across four tabs: Branding, Audience, Clients and Data Access.

1. Go to <https://console.cloud.google.com/> and create a project (e.g. `bugg-anti-cheat`).
2. **Google Auth Platform → Branding** — <https://console.cloud.google.com/auth/branding>
   - App name, user support email, developer contact.
   - **Authorized domains:** add `budotgg.xyz` (the registrable domain, not the
     `verify.` subdomain). Google requires you to prove you own it — see step 6.
3. **Google Auth Platform → Audience** — <https://console.cloud.google.com/auth/audience>
   - User type: **External** (Internal needs a Google Workspace org account).
   - While the app is in **Testing**, add each officer under **Test users**. Only those
     accounts can complete a sign-in; everyone else is refused by Google before the bot
     is ever involved.
   - Switch to **In production** when you want any member to verify. With only the three
     scopes below the app is non-sensitive, so it does not need Google's verification review.
4. **Google Auth Platform → Data Access** — <https://console.cloud.google.com/auth/scopes>
   - Add only `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile`.
     Do **not** add the People API or any Directory scope; this project does not use them.
5. **Google Auth Platform → Clients** — <https://console.cloud.google.com/auth/clients>
   - **Create client → Web application**.
   - **Authorized redirect URIs** — add both:
     ```
     http://localhost:8000/callback
     https://verify.budotgg.xyz/callback
     ```
     One client can hold several. `http` is allowed for `localhost` only; every other
     redirect URI must be `https`, and raw IP addresses are rejected outright — which is
     why the VPS needs a hostname.
   - Copy the client ID and client secret into `.env`.
6. **Verify domain ownership** at <https://search.google.com/search-console>
   - Sign in with the **same Google account that owns the Cloud project**. A mismatch is the
     most common reason verification "passes" but the domain still will not save.
   - Add `budotgg.xyz` as a **Domain** property (the left-hand box), *not* URL prefix.
     Google only accepts DNS-level Domain properties for authorized domains.
   - Copy the `TXT` value it shows and create the record at your registrar, then click Verify.
   - **Leave the record in place.** Google re-checks periodically and will un-verify the
     domain if the TXT record disappears, which silently breaks sign-in.

> The redirect URI must match `BASE_URL` + `/callback` **exactly** — scheme, host, port, path.
> A trailing slash on `BASE_URL` is the usual cause of `redirect_uri_mismatch`; the config
> strips it for you, but keep the console entry clean too.

---

## 2. Discord setup

1. <https://discord.com/developers/applications> → **New Application**.
2. **Bot → Reset Token**, copy it into `DISCORD_TOKEN`. Treat it like a password — anyone
   holding it controls the bot.
3. **Bot → Privileged Gateway Intents**: enable **Server Members Intent**.
   The bot needs it to resolve a member and assign their role. Message Content is *not*
   needed — leave it off.
4. **OAuth2 → URL Generator**:
   - Scopes: `bot`, `applications.commands`
   - Bot permissions: **Manage Roles** and **Kick Members**
   - Open the generated URL and add the bot to your server.
5. **Server Settings → Roles**: drag the bot's own role **above** the verified role.

   ```
   ┌─ Admin
   ├─ Anti-Cheat        ← the bot's role must be higher
   ├─ Verified          ← VERIFIED_ROLE_ID
   └─ @everyone
   ```

   Discord refuses to let a bot assign a role at or above its own position. If this is wrong,
   verification still records the link but the role silently fails — the result page says so
   explicitly rather than claiming success.

   > **BU.gg note:** the server has two similarly named roles. `Verified Member` is the one
   > this bot grants and removes (`VERIFIED_ROLE_ID`). The separate, pre-existing `Verified`
   > role serves a different purpose and the bot never touches it. Don't consolidate them
   > without checking which one your channel permissions are actually built on.
6. Turn on **Developer Mode** (User Settings → Advanced) so you can right-click to copy the
   server, role and user IDs you need for `.env`.

---

## 3. Run it locally

```bash
git clone <your-repo> anti-cheat && cd anti-cheat

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SECRET_KEY
cp roster.csv.example roster.csv   # then add real addresses

python main.py
```

With `BASE_URL=http://localhost:8000`, run `/verify` in Discord and the button will open your
own machine. The whole flow works end to end this way — you do not need a domain to test it.

Run the tests with:

```bash
python -m pytest -v
```

---

## 4. Deploy to the VPS

The bot is served at **`verify.budotgg.xyz`**. A hostname is required, not cosmetic:
**Google rejects raw IP addresses as redirect URIs**, so the VPS cannot be reached by IP alone.

Before deploying, make sure the DNS is in place at your registrar:

| Type | Host | Value | Notes |
|---|---|---|---|
| `A` | `verify` | your VPS IPv4 | the only record the bot needs |
| `AAAA` | `verify` | your VPS IPv6 | only if the VPS has one |
| `TXT` | `@` | `google-site-verification=…` | for Search Console, see step 6 above |

Check it has propagated before reloading Caddy, or the certificate request will fail:

```bash
dig +short verify.budotgg.xyz      # must print your VPS IP
```

```bash
# as root
useradd --system --home /opt/anti-cheat --shell /usr/sbin/nologin anticheat
mkdir -p /opt/anti-cheat
# copy the project into /opt/anti-cheat, then:
cd /opt/anti-cheat
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env
$EDITOR .env                       # set BASE_URL=https://verify.budotgg.xyz
chown -R anticheat:anticheat /opt/anti-cheat
chmod 600 /opt/anti-cheat/.env     # contains the bot token and client secret

cp anti-cheat.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now anti-cheat
systemctl status anti-cheat
```

Then point Caddy at it — append the `Caddyfile` snippet to `/etc/caddy/Caddyfile` (the
hostname `verify.budotgg.xyz` is already filled in), then:

```bash
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
```

Finally, add `https://verify.budotgg.xyz/callback` to the Authorized redirect URIs in the Google
console, and set the matching `BASE_URL` in `.env`. Restart: `systemctl restart anti-cheat`.

Follow the logs with `journalctl -u anti-cheat -f`.

The app listens on `127.0.0.1` only. Nothing but Caddy can reach it, so you do not need to
open the app's port in the firewall — only 80 and 443.

### Updating from GitHub

`/opt/anti-cheat` on the VPS is a git checkout of <https://github.com/exciar/anti-cheat>. It
pulls over SSH with a **read-only deploy key** (`/root/.ssh/anti-cheat-deploy`, registered
under the repo's Settings → Deploy keys). The host alias `github-anti-cheat` in
`/root/.ssh/config` points at it. To ship whatever is on `main`:

```bash
ssh root@your-vps /opt/anti-cheat/deploy.sh
```

The script fetches `main`, installs requirements, runs the test suite and restarts the service.
If the tests fail it rolls the checkout back and leaves the running bot alone. `.env`,
`roster.csv` and the database are untracked, so a deploy never touches them.

---

## 5. Keeping the roster up to date

The roster is a plain CSV with a header row containing an `email` column:

```csv
email
juan.delacruz@bicol-u.edu.ph
maria.santos@bicol-u.edu.ph
```

- Extra columns (name, section, dues paid) are ignored, so you can export straight from a
  spreadsheet without stripping anything out.
- Case and stray spaces do not matter — `  Juan@BICOL-U.edu.ph ` matches
  `juan@bicol-u.edu.ph`.
- A file saved from Excel as "CSV UTF-8" is fine; the byte-order mark is handled.

To update it:

1. Replace `/opt/anti-cheat/roster.csv`.
2. Run `/ac reload-roster` in Discord.

No restart, no downtime. If the new file is malformed, the reload fails with an error message
and **the previous roster stays active** — a bad upload cannot lock everyone out.

Removing someone from the CSV does not revoke anyone already verified. Use `/ac revoke @user`
for that.

### Skipping the roster

Set `ROSTER_MODE=domain_only` to accept any verified `@bicol-u.edu.ph` account without
checking the roster. Useful for a launch day when the roster is not ready. It relaxes *only*
the roster check — the `email_verified` and domain rules still apply.

---

## 6. Kicking members who never verify

Members who never verify are removed after a grace period. Nothing happens until officers
start the clock; from then on every member who isn't verified (and isn't exempt, see below)
is on it:

- **Members who join after the clock starts** get `KICK_AFTER_DAYS` (default 3) from the
  moment they join.
- **Members already in the server when it starts** get `EXISTING_KICK_AFTER_DAYS`
  (default 14) from the moment it starts.

Every deadline lies at least a full grace period after the clock starts, so deploying this or
starting the clock never removes anyone on the spot. The clock only asks whether someone is
verified right now: a member who runs `/unverify`, or is `/ac revoke`d, after their deadline
is removed on the next hourly pass.

### Welcome DM and reminders

New members are DM'd when they join, asking them to run `/verify`. The DM contains
no link on purpose: a link would carry a token bound to their Discord ID, and anyone it
was forwarded to could attach their own school email to that account. Running `/verify`
keeps that token inside an ephemeral reply only they can see. If the clock is running, the
DM also states their deadline.

The server uses **Discord Onboarding**, and that is where members pick their status role
(Undergraduate, Graduate, Outsider…). Discord assigns it only when they finish onboarding,
which is after they join, so the bot waits for that (up to 15 minutes) before deciding whether
to DM them.

Members who were already here when the clock started never got a welcome DM with a deadline,
so on the first hourly pass after `/ac enforce start` each of them gets a one-time notice with
their deadline instead. DMs in a pass go out a second apart so the batch doesn't look like spam
to Discord.

While they are on the clock, the bot also DMs a reminder at each mark in `REMINDER_DAYS`
(default: 7, 3 and 1 day(s) left) that falls inside their grace period — so members on a 3-day
clock get only the 1-day reminder. Each reminder is sent once; after downtime a member gets only
the most urgent one, not several back to back. Members whose DMs are closed simply get nothing
and can still verify normally.

Someone who verified before and rejoins gets their role back automatically, since their
link still exists — no DM, no second verification.

### The sequence

1. Post your announcement in the server explaining that every member must verify.
2. Run **`/ac enforce start`**. From that moment, every member who isn't verified is on the
   clock, and members already here are DM'd their deadline within the hour.
3. **`/ac enforce status`** shows who is on the clock and when each is due.
4. The bot checks hourly: it sends any reminders that are due, then DMs the reason to anyone
   past their deadline and kicks them.

`/ac enforce stop` halts it at any time. Starting it again gives every member who isn't verified
a fresh deadline — anyone in the server at that moment counts as already here.

### Who is never kicked or asked to verify

- Bots
- Verified members
- Anyone with an officer role in `ADMIN_ROLE_IDS`
- Anyone with a role listed in `EXEMPT_ROLE_IDS` — BU.gg lists **Outsider** and **Graduate** here, so
  non-BU members and graduates get no timer and no DMs
- Anyone whose top role sits at or above the bot's — Discord forbids it. `/ac enforce status`
  counts these so they never silently look "handled"; move the bot's role up if you need them
  covered.

### Asked to verify, but never kicked

Anyone with a role in `NO_KICK_ROLE_IDS` runs the same clock — welcome DM or notice, then
reminders — but the DMs leave out the removal warning, and missing the deadline only puts them
in the "past deadline, no-kick role" count in `/ac enforce status`. This works even for a role
ranked above the bot, since only a kick needs the rank. BU.gg lists **Junior Councilor** here.

### Requirements

The bot needs the **Kick Members** permission. If it was invited with only Manage Roles,
re-run the invite with both:

```
https://discord.com/oauth2/authorize?client_id=YOUR_APP_ID&permissions=268435458&scope=bot%20applications.commands
```

Without it, each hourly pass still sends reminders but logs
`bot lacks Kick Members -- skipping this pass` and removes nobody.

Kicked members can rejoin and verify — this is a kick, never a ban. Each kick is recorded in
`attempts` with outcome `kicked`.

---

## Privacy notes

- Stored per member: email, the `name` claim from the Google ID token, Discord ID, guild ID,
  and the verification timestamp. That is the whole record (`links` table). The name is
  disclosed on the consent page before sign-in, and is there so officers can match an
  account to the org's membership records — older school addresses are opaque student
  numbers that identify nobody on their own.
- The `attempts` table logs Discord ID, outcome and timestamp for auditing. It has no column
  capable of holding a token, an OAuth code or an email.
- **`/unverify` also anonymizes that member's audit rows** — their Discord ID is set to `NULL`
  while the outcomes remain, so `/ac stats` counts stay accurate but nothing in the database
  points back at them. `/ac revoke` deliberately keeps the Discord ID: that is an officer
  action and doubles as a moderation record.
- The `reminders` table records which reminder DMs a member on the kick clock has been
  sent (Discord ID, deadline, stage). Rows are dropped once the member verifies, leaves,
  is kicked or runs `/unverify`.
- Tokens and authorization codes are never logged. uvicorn's access log is disabled and
  Caddy's is discarded, because both would otherwise record the query string containing them.
- `/unverify` deletes the member's row immediately, with no officer approval needed.
- `roster.csv` and `anticheat.db` are in `.gitignore` — they contain student personal data
  and must not be committed.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `redirect_uri_mismatch` | `BASE_URL` + `/callback` does not exactly match the console entry |
| "Verified, but the role didn't apply" | The bot's role sits below `VERIFIED_ROLE_ID` |
| Commands do not appear | Wrong `GUILD_ID`, or the bot was invited without `applications.commands` |
| "This link expired" | Links last 10 minutes; run `/verify` again |
| Everyone gets "not on roster" | `ROSTER_PATH` points at the wrong file — check `/ac stats` for the loaded count |
