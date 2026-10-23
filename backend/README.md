# Sanga backend

Go stdlib-only API. Currently exposes `GET /health` only.

## Run

```sh
cd backend
go mod tidy
PORT=8080 DATABASE_PATH=data/sanga.db go run ./cmd/server
```

Check:

```sh
curl -i localhost:8080/health
# {"status":"ok"}
```

## Layout

- `cmd/server/main.go` – wiring, graceful shutdown
- `internal/config` – env (`PORT`, `DATABASE_PATH`)
- `internal/db` – SQLite open (`modernc.org/sqlite`)
- `internal/http` – router + `GET /health`
