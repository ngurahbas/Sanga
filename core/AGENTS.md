# AGENTS.md

Extends [`../AGENTS.md`](../AGENTS.md).

Go rules:
- `//go:` directives and tool-generated markers (`// indirect`) are not comments; leave them alone.

## Run

```sh
cd core
go mod tidy
PORT=8080 DATABASE_PATH=./sanga.db SANGA_ADMIN_KEY_FILE=./admin.key go run ./cmd/server
```

Defaults: `PORT=8080`, `SANGA_HOST=""` (all interfaces), `DATABASE_PATH=./sanga.db`,
`SANGA_ADMIN_KEY_FILE=./admin.key`, `SANGA_ROOT_USERNAME=root`. Paths are relative to the
process working directory; wrappers should pass absolute paths. `SANGA_HOST=127.0.0.1` binds loopback.

Health checks:

- `GET /health` — process is up.
- `GET /ready` — database responds.

## Bootstrap (root admin)

- On startup, after migrate: if no `role='admin'` exists, bootstrap creates one.
- If an admin exists and has at least one active key, bootstrap is a no-op; the key file is ignored.
- If an admin exists but has no active key, bootstrap recovers by importing the key file or generating a new key for the first admin. This is the lockout recovery path.
- If `SANGA_ADMIN_KEY_FILE` exists, its `<id>.<secret>` is imported for the new root admin, or for the first existing admin during recovery.
- Else: generates a key, claims the key file (`0600`, `O_EXCL`) first, then creates root + stores the hash in one transaction. Prints path + ID. Keep it secret.
- Pre-existing `root` name with a non-admin role: startup errors (no silent promote). Pick another `SANGA_ROOT_USERNAME` or promote manually.
- Invalid/empty key file with no active admin key: startup fails fast, no partial user.
- The generated raw key exists only in the key file; the database stores only its hash. Revoking the last active key of the last admin is refused.
- Deleting a user cascades to their owned documents, shares, and keys. There is no soft delete or transfer step.

## API

The HTTP layer uses the standard library. SQLite uses `modernc.org/sqlite`. JSON APIs are under
`/api`; this leaves `/` and `/docs/{id}` free for the future frontend. Authentication is
`X-API-Key` or `Authorization: Bearer`; errors are JSON `{"error":"..."}` (401 also sends `WWW-Authenticate`).

### Users API

| Method | Path | Who |
|---|---|---|
| `POST` | `/api/users` | admin |
| `GET` | `/api/users`, `/api/users/{id}`, `/api/users/me` | any authenticated user |
| `DELETE` | `/api/users/{id}` | admin (refuses last admin) |
| `POST` | `/api/users/{id}/keys` | admin any, self own (max 10 active) |
| `GET` | `/api/users/{id}/keys` | admin any, self own (metadata only) |
| `POST` | `/api/users/{id}/keys/{keyID}/rotate` | admin any, self own |
| `DELETE` | `/api/users/{id}/keys/{keyID}` | admin any, self own (refuses last admin key) |

Issue/rotate return `{"key": {...}, "raw": "<id>.<secret>"}` with `Cache-Control: no-store` — raw is shown once, never stored.
Key names are at most 100 chars. The active-key cap is enforced atomically. Keys are permanent and
have no scopes; rotate or revoke them explicitly.

### Docs API

Docs are knowledge-base entries: `{title, body (markdown), visibility, tags, shared_with}`.
Title 1-200 chars, body 1-100 KiB, tags max 10 of `[a-z0-9-]`, 1-32 chars each, normalized lowercase.
`shared_with` max 100 user IDs and only allowed on private docs; the owner cannot be shared.
Read: `public` = any authenticated user; `private` = owner/admin/shared users only (strangers get `404`).
Write/share: owner or admin only (shared users are read-only). `shared_with` is returned only to
readers who can write. List responses omit `body`.

| Method | Path | Who / notes |
|---|---|---|
| `POST` | `/api/docs` | any authenticated user; owner=caller. Body `{title, body, visibility="public", tags:[], shared_with:[userIDs]}` |
| `GET` | `/api/docs?limit=&offset=&tag=&owner=&visibility=` | summaries only, no body; readable docs; admin sees all. `owner` is a user ID. Default limit 50, max 100 |
| `GET` | `/api/docs/{id}` | readable only, else `404`; includes body |
| `PATCH` | `/api/docs/{id}` | owner/admin. Partial `{title?, body?, visibility?, tags?}`; omitted fields are untouched. `visibility` must be exactly `public` or `private` when present |
| `DELETE` | `/api/docs/{id}` | owner/admin, `204` |
| `PUT` | `/api/docs/{id}/shares` | owner/admin, private docs only. Body `{user_id}` |
| `DELETE` | `/api/docs/{id}/shares/{userID}` | owner/admin, `204` (`404` if share missing) |

Per-user document quota is 1000. TLS, CORS, and rate limiting are wrapper responsibilities; core has none.

## Layout

- `cmd/server/main.go` – config, lifecycle, graceful shutdown
- `server` – public `NewHandler(*sql.DB)` seam for an in-process wrapper; HTTP is the contract
- `internal/api` – router, health/ready, users + docs handlers
- `internal/httpx` – JSON responses, decoding, request body limit
- `internal/config` – env (`PORT`, `SANGA_HOST`, `DATABASE_PATH`, `SANGA_ADMIN_KEY_FILE`, `SANGA_ROOT_USERNAME`)
- `internal/db` – SQLite open, DSN pragmas, versioned migrations, file permissions
- `internal/storeutil` – IDs and fixed-width timestamps
- `internal/auth` – API keys (`Issue`, `ImportRawKey`, `Authenticate`, `WithAuth`)
- `internal/bootstrap` – root admin ensure, import, recovery
- `internal/user` – users, atomic last-admin delete
- `internal/doc` – markdown docs (`Store`, validation, `CanRead`/`CanWrite`)
