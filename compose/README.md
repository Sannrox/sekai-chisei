# Compose harness

Starts the ADR 0082 pair on loopback: Sekai on `:50051`, Chisei on `:50052`.
One volume for the Sekai database. Chisei has none.

```bash
docker compose -f compose/two-planes.yaml up --build
```

Without Docker, use the cargo commands in
[docs/two-local-servers.md](../docs/two-local-servers.md).
