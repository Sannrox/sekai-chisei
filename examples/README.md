# Examples

Runnable examples for the `sekai-chisei` control plane. Each one is a standalone
binary that links the library crate and talks to a running gRPC server.

## demo_client

[demo_client.rs](demo_client.rs) is an end-to-end client that walks through a
realistic "AI-assisted delivery" slice: it builds a small typed-object graph in
`sekai`, then drives the `chisei` budget and decision pipeline. Every call is
tolerant — a failing step is reported and the run continues — so it doubles as a
local smoke test.

### Run it

Start the server in one terminal:

```bash
SEKAI_INSECURE=1 cargo run
```

Run the demo in another:

```bash
cargo run --example demo_client
```

### What it does

**sekai · typed object graph**

- Creates a `namespace` object and a `service` object
- Links them `namespace --deploys--> service`
- Reads the relationship back with `GetLinkedObjects`
- Traverses the graph outward from the namespace
- Lists objects filtered by `kind`

**chisei · budget & decision pipeline**

- Sets a daily token budget for a user
- Checks the budget, then records usage and checks again
- Resolves a model policy for the namespace/namespace
- Runs the decision pipeline over a task spec and prints each step's action,
  confidence, and reasoning

**chisei · execute (live LLM call)**

- Calls `PlanExecution` to build a budget- and policy-resolved execution plan
- Calls `ExecutePlan`, which actually invokes the model and prints its reply
- Defaults to a **local Ollama** model (`ollama/llama3.2:latest`)

This is the only part of the demo that makes a real model call. It needs a
reachable provider for the resolved model — by default a local Ollama server at
`OLLAMA_URL` (`http://localhost:11434`) with the model pulled:

```bash
ollama pull llama3.2
```

If the model is not reachable, the step reports the error and the demo still
finishes.

### Configuration

The example honors the same environment variables as the server:

| Variable | Default | Effect |
| --- | --- | --- |
| `GRPC_PORT` | `50051` | Port to connect to |
| `SEKAI_AUTH_TOKEN` | unset | When set, attaches `authorization: Bearer <token>` to every request |
| `DEMO_MODEL` | `ollama/llama3.2:latest` | Model used for the live execute step |

It always sends `x-principal: demo-client` as the caller identity.

> The model provider is configured on the **server**, not the client. The server
> routes `ollama/<tag>` models to its `OLLAMA_URL`, so the Ollama server must be
> reachable from wherever `sekai-chisei` is running.

### Notes

- Object and link ids carry a random suffix per run, so repeated invocations do
  not collide.
- The pipeline resolves a namespace by its own naming convention rather than the
  demo's generated object id, so it reports `namespace not found in sekai` for the
  enrichment steps. That is expected — the graph object and the pipeline's namespace
  lookup are independent in this demo.
