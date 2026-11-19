# Sanga

Sanga is an application to share knowledge between humans and AI agents. Sanga uses API keys for authentication.

## Layout

- `core/` — Go API and future embedded frontend. See [`core/AGENTS.md`](core/AGENTS.md) for the API, layout, running, and bootstrap details.

## Run

```sh
cd core
go mod tidy
PORT=8080 DATABASE_PATH=./sanga.db SANGA_ADMIN_KEY_FILE=./admin.key go run ./cmd/server
```

Or from the repository root:

```sh
make run
```

Check:

```sh
curl -i localhost:8080/health
# {"status":"ok"}
```
