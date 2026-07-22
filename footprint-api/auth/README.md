# Authentication & Authorization

Self-contained login system protecting the Digital Footprint Dashboard's API and frontend. No third-party identity provider (no Cognito, Auth0, Firebase, OAuth) — everything lives in this folder, backed by its own SQLite database, completely separate from the DynamoDB-backed dashboard data in `../app.py`.

## What it does

- Username/password login, issuing a short-lived JWT **access token** (60 min) plus a rotating **refresh token** stored in an HttpOnly cookie.
- Three roles — **Admin**, **Analyst**, **Viewer** — enforced on every protected endpoint, both the new `/api/v1/auth/*` routes and the pre-existing dashboard/AWS endpoints in `app.py`.
- Password hashing (bcrypt), account lockout after repeated failures, per-IP login rate limiting, and an audit log of every auth-related event.
- A React login page, session context, and route guard on the frontend (`frontend/src/features/auth/`, `frontend/src/context/AuthContext.tsx`) that this backend serves.

## File-by-file

| File | Purpose |
|---|---|
| `database.py` | Creates the SQLite engine (`auth.db`, this folder) and the `get_session()` dependency every other file uses. |
| `models.py` | SQLModel tables: `User`, `RefreshToken`, `AuditLog`. Also `utcnow()` — every timestamp in this system is naive-but-UTC by convention (SQLite silently drops timezone info on write, so mixing aware/naive datetimes here will raise `TypeError`). |
| `security.py` | bcrypt password hashing, refresh-token generation/hashing (`secrets` + SHA-256), account lockout state machine, per-IP login rate limiter. |
| `jwt.py` | Creates and verifies the JWT **access token** only (PyJWT). The refresh token is a plain random string, not a JWT — see `security.py`. |
| `schemas.py` | Pydantic request/response models. `UserRead` is the only shape ever returned for a user — it excludes `password_hash` and lockout bookkeeping. |
| `dependencies.py` | FastAPI `Depends()` functions: `get_current_user`, `require_admin`, `require_analyst_or_admin`. Re-checks the database on every request (not just the JWT claims), so a disabled account or role change takes effect on the very next request instead of waiting for the token to expire. |
| `services.py` | The actual business logic — login, refresh-token rotation, logout, password change, user CRUD — plus audit logging. Raises `HTTPException` directly; routes stay thin. |
| `routes.py` | The FastAPI router, mounted at `/api/v1/auth` in `app.py`. |
| `create_admin.py` | One-time CLI to create the first admin account (see below) — nothing else can, once every endpoint requires auth. |
| `auth.db` | The SQLite file itself. Gitignored (`footprint-api/auth/auth.db*` in the repo root `.gitignore`) — it holds password hashes. |

## Installing the required tools

Everything needed is in `footprint-api/requirements.txt`. From the repo root:

```bash
pip3 install -r footprint-api/requirements.txt
```

This installs the three packages this system adds on top of the existing FastAPI stack:

| Package | Version | What it's for |
|---|---|---|
| `sqlmodel` | 0.0.39 | Typed ORM over the SQLite file — table definitions in `models.py`, queries in `services.py`. |
| `bcrypt` | 5.0.0 | Password hashing. Used directly (not via `passlib`, which has had version-compatibility breaks with recent bcrypt releases). |
| `PyJWT` | 2.13.0 | Encodes/verifies the access token in `jwt.py`. |

**SQLite itself needs no separate install** — it's Python's built-in `sqlite3` module (stdlib), which `sqlmodel`/SQLAlchemy use under the hood. There's no server to run and no service to start; `auth.db` is just a file that gets created automatically.

## Required environment variable

```bash
AUTH_JWT_SECRET=<a long random string>
```

Generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

The API **fails to start signing tokens at all** (raises `RuntimeError`) if this isn't set — there is no insecure default to fall back to.

Two ways to set it, both work — `app.py` calls `load_dotenv()` on startup:
- Export it in your shell: `export AUTH_JWT_SECRET=...` before running `uvicorn app:app`.
- Or put it in a `.env` file in `footprint-api/` (or anywhere above it — `load_dotenv()` searches upward): `AUTH_JWT_SECRET=...`. This is the same mechanism `main.py` already uses for its own config, and it's how `AWS_REGION`/`DYNAMODB_TABLE_NAME`/etc. can be set too if you'd rather not export them each time.

If you still get `RuntimeError: AUTH_JWT_SECRET is not set` with a `.env` file in place, double-check the file is actually named `.env` (not `.env.txt`) and sits in `footprint-api/` or a parent directory of it, and that the line has no surrounding quotes or spaces around the `=` (`AUTH_JWT_SECRET=abc123`, not `AUTH_JWT_SECRET = "abc123"`).

## Optional environment variable

```bash
AUTH_COOKIE_SECURE=1   # default; the refresh-token cookie requires HTTPS (or localhost, which
                       # modern browsers exempt)
```

Set `AUTH_COOKIE_SECURE=0` only for local testing against a non-`localhost` address (e.g. a raw LAN IP) over plain HTTP. Never set this in a real deployment — it would let the refresh token travel unencrypted.

## First-time setup: creating the first admin account

Once every endpoint requires login, nothing can call the admin-only `POST /api/v1/auth/users` to create the *first* user — that's what this script is for. Run it once, from `footprint-api/`:

```bash
py -m auth.create_admin
```

It prompts for a username, email, and password (password entry is hidden via `getpass`, and asks for confirmation). Non-interactive/scripted use is also supported:

```bash
py -m auth.create_admin --username admin --email admin@example.com --password '...'
```

Avoid `--password` outside of scripts — it's left sitting in shell history. Prefer the interactive prompt for a real account.

## Roles & permissions

| | Admin | Analyst | Viewer |
|---|---|---|---|
| View dashboard (`GET /api/v1/dashboard`) | ✅ | ✅ | ✅ |
| View raw findings (`GET /findings*`) | ✅ | ✅ | ❌ |
| AI Summary (`POST /api/cve-analysis`) | ✅ | ✅ | ❌ (billed Lambda call) |
| Trigger a re-scan (`POST /api/v1/dashboard/refresh`) | ✅ | ❌ | ❌ |
| Manage users (`/api/v1/auth/users*`) | ✅ | ❌ | ❌ |

The frontend mirrors this: the Refresh button only renders for Admin, and the Ask AI panel is hidden entirely for Viewer. These are UX conveniences, not the actual security boundary — the boundary is enforced server-side via `dependencies=[Depends(require_admin)]` / `require_analyst_or_admin` on each route.

## API endpoints

| Endpoint | Method | Auth required | Notes |
|---|---|---|---|
| `/api/v1/auth/login` | POST | No | Sets the refresh-token cookie; returns the access token in the JSON body. |
| `/api/v1/auth/refresh` | POST | Refresh cookie | Rotates the refresh token (old one is revoked immediately). |
| `/api/v1/auth/logout` | POST | Yes | Revokes the current refresh token, clears the cookie. |
| `/api/v1/auth/change-password` | POST | Yes | Revokes every other active session on success. |
| `/api/v1/auth/forgot-password` | POST | No | **Placeholder** — logs the request, does not send an email. Always returns the same message whether or not the email is registered. |
| `/api/v1/auth/me` | GET | Yes | Current user's profile. |
| `/api/v1/auth/users` | GET / POST | Admin | List / create users. |
| `/api/v1/auth/users/{id}` | PUT / DELETE | Admin | Update (role, active status, password reset) / delete. An admin can neither delete nor disable their own account (both blocked server-side, `400`) — either one would lock them out with no way back in except direct database access. An admin also can't demote their own role away from Admin *if they're the only active admin* — allowed as soon as at least one other active admin exists (`services._has_other_active_admin`). |

## Security details worth knowing

- **Access token**: JWT, 60-minute expiry, HS256, signed with `AUTH_JWT_SECRET`. Stateless — cannot be revoked before it expires on its own, which is why it's kept short-lived.
- **Refresh token**: a random 512-bit string (`secrets.token_urlsafe`), never a JWT. Only its SHA-256 hash is stored in `auth.db` — a leaked database row can't be used as a credential. **Rotated on every use**: each `/refresh` call revokes the token it was given and issues a new one, so a stolen-and-replayed old refresh token fails.
- **Account lockout**: 5 failed login attempts locks the account for 15 minutes (`security.MAX_FAILED_LOGIN_ATTEMPTS` / `LOCKOUT_DURATION`).
- **Rate limiting**: 10 login attempts per minute per IP, in-memory (resets on API restart — a coarse "slow down a spray across many usernames" guard, not a replacement for the per-account lockout above).
- **Audit log**: every login (success/failure), logout, password change, and admin user-management action is recorded in the `AuditLog` table with username, action, IP, timestamp, and success/failure.
- **No user enumeration**: unknown username and wrong password return the identical error message; `/forgot-password` returns the identical response regardless of whether the email is registered.

## Managing accounts from the frontend

Admins get a dedicated **Manage users** page (`/users`, its own sidebar entry under Reference) — create accounts, change roles, disable/re-enable, or permanently delete, all backed by the endpoints above. New accounts default to Viewer unless a different role is picked at creation time. Non-admins never see the sidebar link, and typing the URL directly redirects them away (`RequireAdmin` in the frontend router) — the actual boundary is still server-side (`require_admin`), this is just the matching UI treatment. There is no public self-signup — every account is still created by an admin.

Disabling or re-enabling **someone else's** account asks for confirmation first (a plain browser confirm dialog, stating what's about to happen — e.g. "Disable 'x'? They won't be able to log in until this is reversed."). Deleting any account also confirms, since that one's permanent. Your own row's toggle is simply disabled (can't click it at all) rather than confirmed, since disabling yourself is never allowed anyway.

## What this system does *not* do

- No email sending — `/forgot-password` is a logged placeholder, per the spec.
- No per-role restriction on which *dashboard pages* a role can navigate to. All three roles can reach every page — the data behind those pages all comes from the one `GET /api/v1/dashboard` call, which every authenticated role can read. The real per-role boundaries are the ones in the table above (refresh, findings, AI summary, user management).
