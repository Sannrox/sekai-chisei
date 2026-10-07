# Two-plane processes

Independently runnable `sekai-plane` and `chisei-plane` processes prove the
stores are separate. Combined `sekai-chisei` remains the default local binary
and still opens the typed two-store contract. The ontology CLI keeps the
`sekai` binary name.

## What each process opens

| Process | Store | Credentials | Public service |
| --- | --- | --- | --- |
| `sekai-plane` | `SEKAI_DB_PATH` or `SEKAI_DATABASE_URL`; with none set, `<SEKAI_DATA_DIR>/sekai.db`. `DB_PATH` / `DATABASE_URL` / `SEKAI_SHARED_STORE` refuse boot | Sekai store only | `SekaiService` |
| `chisei-plane` | `CHISEI_DB_PATH` or `CHISEI_DATABASE_URL`; with no store variable set, `<SEKAI_DATA_DIR>/chisei.db` | no local catalog (Sekai-owned); UDS uses the local principal | `ChiseiService` |
| `sekai-chisei` | dest-pair (`SEKAI_DB_PATH`+`CHISEI_DB_PATH` or the two Postgres URLs); with no store variable set, both files under `SEKAI_DATA_DIR` (default `./data`). `DB_PATH` / `DATABASE_URL` / `SEKAI_SHARED_STORE` refuse boot | Sekai store (combined) | both |

A Sekai process refuses `CHISEI_DB_PATH` / `CHISEI_DATABASE_URL`. A Chisei
process refuses `SEKAI_DB_PATH` / `SEKAI_DATABASE_URL`. Each physical store is
stamped on first open; the other process cannot open that file or URL. Each
process migrates only the tables its plane owns, plus the shared decision
ledger and the per-store `chisei_operation_receipts` table. Combined Split
writes plane-local admission receipts onto the Sekai dest.

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

## Sekai facts in Chisei

Lookup-first and pipeline object context read Sekai facts (objects, links,
grants, schemas) through a Chisei-owned read port, never from the Chisei
store. Combined mode reads the Sekai dest in process. A Chisei process reads over the same `SEKAI_ENDPOINT` hop with
public `SekaiService` RPCs, which Sekai authorizes for the hop credential;
Chisei then narrows to the request actor. Graph retrieval for lookup-first has
no public RPC, so on the hop lookup-first refuses with
`sekai_read_unsupported` and takes the model path.

Context authorization reads namespace-boundary and object grants, which Sekai
serves only to an admin credential. With a less privileged `SEKAI_CREDENTIAL`
those reads are refused and object context is dropped, not leaked. A namespace
boundary the hop credential cannot see is not treated as absent, so a namespace
without a visible boundary yields no context for non-local actors over the hop.
An unreachable Sekai skips object context with `sekai_read_failed`. Without
`SEKAI_ENDPOINT`, lookup-first refuses with `sekai_not_attached` and object
context injection is skipped with the same reason.

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
