# Two-plane processes

Independently runnable `sekai-plane` and `chisei-plane` processes prove the
stores are separate. Combined `sekai-chisei` remains the default local binary
and still opens the typed two-store contract. The ontology CLI keeps the
`sekai` binary name.

## What each process opens

| Process | Store | Credentials | Public service |
| --- | --- | --- | --- |
| `sekai-plane` | `SEKAI_DB_PATH` or `SEKAI_DATABASE_URL` (or legacy `DB_PATH` / `DATABASE_URL`) | Sekai store only | `SekaiService` |
| `chisei-plane` | `CHISEI_DB_PATH` or `CHISEI_DATABASE_URL` | Chisei store only | `ChiseiService` |
| `sekai-chisei` | dest-pair (`SEKAI_DB_PATH`+`CHISEI_DB_PATH` or the two Postgres URLs). Shared one-identity boot only with `SEKAI_SHARED_STORE=1` | Sekai store (combined) | both |

A Sekai process refuses `CHISEI_DB_PATH` / `CHISEI_DATABASE_URL`. A Chisei
process refuses `SEKAI_DB_PATH` / `SEKAI_DATABASE_URL`. Each physical store is
stamped on first open; the other process cannot open that file or URL.

## Wrong-plane RPCs

Calling `GetOperationReceipt` on the Sekai listener, or `SubmitActionInstance`
on the Chisei listener, returns `FAILED_PRECONDITION` (`wrong-plane: this
process serves …`). Combined mode serves both.

## Authenticated hop

A Chisei process looks up a live Sekai commit through `SEKAI_ENDPOINT` and
optional `SEKAI_CREDENTIAL`. The hop is a caller credential, not a stored
Chisei decision. Sekai rechecks current authorization on `SubmitActionInstance`
and on the commit lookup.

`GetOperationReceipt` on Chisei projects that live commit handle. It does not
copy the Sekai receipt body into the Chisei store.

## Gateway

`chisei-gateway` remains a protocol translator. It does not open a third
durable store.

## Local example

```sh
SEKAI_INSECURE=1 SEKAI_BIND=127.0.0.1 GRPC_PORT=50051 \
  SEKAI_DB_PATH=./data/sekai.db SEKAI_SOCKET= OPS_PORT= SEKAI_HTTP_PORT= \
  cargo run --bin sekai-plane

SEKAI_INSECURE=1 SEKAI_BIND=127.0.0.1 GRPC_PORT=50052 \
  CHISEI_DB_PATH=./data/chisei.db SEKAI_ENDPOINT=http://127.0.0.1:50051 \
  SEKAI_SOCKET= OPS_PORT= SEKAI_HTTP_PORT= \
  cargo run --bin chisei-plane
```

Submit stays `SubmitActionInstance` on the Sekai process. Receipt lookup is
`GetOperationReceipt` on the Chisei process.
