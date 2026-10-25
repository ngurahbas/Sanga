# Sanga backend

Go stdlib-only API. `GET /health` (public) + authenticated `/users` and `/docs`.

## Run

```sh
cd backend
go mod tidy
PORT=8080 DATABASE_PATH=./sanga.db SANGA_ADMIN_KEY_FILE=./admin.key go run ./cmd/server
```

Check:

```sh
curl -i localhost:8080/health
# {"status":"ok"}
```

## Bootstrap (root admin)

- Default DB is `./sanga.db` (note: previously `data/sanga.db` — move your file if upgrading).
- On startup, after migrate: if no `role='admin'` exists, bootstrap runs.
- If `SANGA_ADMIN_KEY_FILE` (default `./admin.key`) exists: imports its `<id>.<secret>` for user `root`/`SANGA_ROOT_USERNAME` (admin).
- Else: generates a key, claims the key file (`0600`, `O_EXCL`) first, then creates root + stores hash. Prints path + ID. Keep it secret. File claim before DB insert, so a failed write never orphans a key; a failed DB store keeps the file for retry on next restart.
- Pre-existing `root` name with non-admin role: startup errors (no silent promote). Pick another `SANGA_ROOT_USERNAME` or promote manually.
- If an admin already exists: no-op, key file ignored.
- Invalid/empty key file with no admin: startup fails fast, no partial user.

## Users API (auth: `X-API-Key` or `Bearer`)

| Method | Path | Who |
|---|---|---|
| `POST` | `/users` | admin |
| `GET` | `/users`, `/users/{id}`, `/users/me` | any authenticated user |
| `DELETE` | `/users/{id}` | admin (refuses last admin) |
| `POST` | `/users/{id}/keys` | admin any, self own (max 10 active) |
| `GET` | `/users/{id}/keys` | any authenticated user (metadata only) |
| `POST` | `/users/{id}/keys/{keyID}/rotate` | admin any, self own |
| `DELETE` | `/users/{id}/keys/{keyID}` | admin any, self own |

Issue/rotate return `{"key": {...}, "raw": "<id>.<secret>"}` — raw is shown once, never stored.

## Docs API (auth: `X-API-Key` or `Bearer`, raw markdown only)

Docs are knowledge-base entries: `{title, body (markdown), visibility, tags, shared_with}`.
Title 1-200 chars, body 1-100 KiB, tags max 10 of `[a-z0-9-]` (normalized lowercase).
Read: `public` = any authenticated user; `private` = owner/admin/shared users only (strangers get `404`).
Write/share: owner or admin only (shared users are read-only).

| Method | Path | Who / notes |
|---|---|---|
| `POST` | `/docs` | any authenticated user; owner=caller. Body `{title, body, visibility="public", tags:[], shared_with:[userIDs]}` |
| `GET` | `/docs?limit=&offset=&tag=&owner=&visibility=` | only readable docs; admin sees all |
| `GET` | `/docs/{id}` | readable only, else `404` |
| `PATCH` | `/docs/{id}` | owner/admin. Partial `{title?, body?, visibility?, tags?}` |
| `DELETE` | `/docs/{id}` | owner/admin, `204` |
| `PUT` | `/docs/{id}/shares` | owner/admin, private docs only. Body `{user_id}` |
| `DELETE` | `/docs/{id}/shares/{userID}` | owner/admin, `204` (`404` if share missing) |

## Layout

- `cmd/server/main.go` – wiring, graceful shutdown
- `internal/config` – env (`PORT`, `DATABASE_PATH`, `SANGA_ADMIN_KEY_FILE`, `SANGA_ROOT_USERNAME`)
- `internal/db` – SQLite open (`modernc.org/sqlite`)
- `internal/auth` – API keys (`Issue`, `ImportRawKey`, `Authenticate`, `WithAuth`)
- `internal/bootstrap` – root admin ensure (import or generate)
- `internal/doc` – markdown docs (`Store`, validation, `CanRead`/`CanWrite`)
- `internal/http` – router + `GET /health`, users + docs handlers
