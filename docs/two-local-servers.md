# Two local servers

ADR [0082](decisions/0082-two-local-servers.md): Sekai is the Foundry-shaped
clerk; Chisei is the AIP-shaped platform. They are two loopback gRPC
processes. One Sekai database. Chisei has none. This repository is the
implementation SoR and the two-process proof
(`tests/two_process_planes.rs`).

```text
OpenAI / Anthropic clients     PlanExecution / InvokeActionInstance
         |                            |
         v                            v
              Chisei  (loopback :50052)
              route, policy, admit or deny
         |                    |
         | LLM provider       | clerk RPCs
         v                    v
                    Sekai  (loopback :50051)
                    objects, ACL, persist, one DB
```

## Operator path

Start Sekai, then Chisei. Point the gateway at Chisei.

```bash
cp .env.example .env
SEKAI_INSECURE=1 cargo run --locked --bin sekai
```

```bash
SEKAI_INSECURE=1 \
  CHISEI_SEKAI_ENDPOINT=http://127.0.0.1:50051 \
  GRPC_PORT=50052 \
  cargo run --locked --bin chisei
```

Compose map: [`compose/two-planes.yaml`](../compose/two-planes.yaml).

```bash
docker compose -f compose/two-planes.yaml up --build
```

## Proof

`tests/two_process_planes.rs` starts both planes on loopback, reads an object
from Sekai, invokes through Chisei, and reads the receipt Sekai persisted.

```bash
cargo test --locked --test two_process_planes
```

## Auth

Credentials stay in Sekai. Chisei forwards `authorization` and fails closed if
Sekai rejects.
