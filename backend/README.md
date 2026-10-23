# Sanga backend

Go stdlib-only API. Currently exposes `GET /health` only.

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
- Else: generates a key, claims the key file (`0600`, `O_EXCL`) first, then creates root + stores hash. Prints path + id. Keep it secret. File claim before DB insert, so a failed write never orphans a key; a failed DB store keeps the file for retry on next restart.
- Pre-existing `root` name with non-admin role: startup errors (no silent promote). Pick another `SANGA_ROOT_USERNAME` or promote manually.
- If an admin already exists: no-op, key file ignored.
- Invalid/empty key file with no admin: startup fails fast, no partial user.

## Users API (auth: `X-API-Key` or `Bearer`)

| Method | Path | Who |
|---|---|---|
| `POST` | `/users` | admin |
| `GET` | `/users`, `/users/{id}`, `/users/me` | any authed |
| `DELETE` | `/users/{id}` | admin (refuses last admin) |
| `POST` | `/users/{id}/keys` | admin any, self own (max 10 active) |
| `GET` | `/users/{id}/keys` | any authed (metadata only) |
| `POST` | `/users/{id}/keys/{keyID}/rotate` | admin any, self own |
| `DELETE` | `/users/{id}/keys/{keyID}` | admin any, self own |

Issue/rotate return `{"key": {...}, "raw": "<id>.<secret>"}` — raw is shown once, never stored.

## Layout

- `cmd/server/main.go` – wiring, graceful shutdown
- `internal/config` – env (`PORT`, `DATABASE_PATH`, `SANGA_ADMIN_KEY_FILE`, `SANGA_ROOT_USERNAME`)
- `internal/db` – SQLite open (`modernc.org/sqlite`)
- `internal/auth` – API keys (`Issue`, `ImportRawKey`, `Authenticate`, `WithAuth`)
- `internal/bootstrap` – root admin ensure (import or generate)
- `internal/http` – router + `GET /health`
