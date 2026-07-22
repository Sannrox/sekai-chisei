# Examples

## Reference capability host

`capability_reference_host` is a host-neutral reference consumer for the agent-facing
capability catalog. It discovers a governed action from the live namespace
catalog, binds the projected public contract, invokes it, presents or resolves
an approval, and retrieves the causal operation report. The host contains no
compiled list of Chisei actions.

```bash
CAPABILITY_NAMESPACE=default \
CAPABILITY_NAME=sekai.actions.set_property \
CAPABILITY_INPUT='{"id":"object-1","key":"status","value":"reviewed"}' \
SEKAI_INSECURE=1 cargo run --example capability_reference_host
```

Set `CAPABILITY_APPROVAL=approve` or `deny` to demonstrate operator handling when
policy holds the discovered action. Production deployments use
`SEKAI_AUTH_TOKEN` and a scoped `SEKAI_PRINCIPAL`; insecure mode is local-only.

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

## governed_tool_use

[governed_tool_use.rs](governed_tool_use.rs) demonstrates the governed tool-use
bridge: it maps a model tool-call to an `ExecuteAction` request — the
single enforcement point — so the call is policy-checked, dry-run-able,
held-for-approval, budget-limited, and audited before any graph mutation.

```bash
SEKAI_INSECURE=1 cargo run          # server in one terminal
cargo run --example governed_tool_use   # demo in another
```

It seeds a target object, sets an action policy (allow writes, require approval
for destructive ops), then runs tool-calls through `ExecuteAction`: a write is
dry-run and executed, a destructive `delete_link` is held for approval, and the
pending approvals are listed. In `SEKAI_INSECURE=1` mode the `local` principal is
an admin, so setting policy and listing approvals succeed.

## delegation

[delegation.rs](delegation.rs) sketches the privacy-preserving delegation chain:
local Ollama planning with private context, a frontier `template_only` rubric
request, local private composition, and a leak-checked `template_only` polish
pass. It prints the `PlanExecution` request sequence without making network or
model calls:

```bash
cargo run --example delegation
```

### Configuration

The example honors the same environment variables as the server:

| Variable | Default | Effect |
| --- | --- | --- |
| `GRPC_PORT` | `50051` | Port to connect to |
| `SEKAI_SOCKET` | unset | Unix socket path to connect to instead of TCP |
| `SEKAI_AUTH_TOKEN` | unset | When set, attaches `authorization: Bearer <token>` to every request (deprecated fallback to principal `root`; prefer per-principal tokens from `sekaictl credential ...`) |
| `SEKAI_PRINCIPAL` | `demo-client` | Caller identity (`x-principal`) sent in request metadata |
| `DEMO_MODEL` | `ollama/llama3.2:latest` | Model used for the live execute step |

It sends caller identity via `x-principal` using `SEKAI_PRINCIPAL`.

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

## incident_response

[incident_response.rs](incident_response.rs) shows a non-coding domain using
only the core Sekai contract. A service incident is represented as a namespace,
actor, operation, attempt, action, artifact, verification, and outcome connected
by ordinary links. No incident-specific field, RPC, application scope, workflow
engine, or agent runtime is added to the control plane.

The example builds and prints the graph locally without starting the server:

```bash
cargo run --example incident_response
```

An integration can persist the same objects and links through `SekaiService`,
then submit the operation through the Chisei gateway or native execution API.
Incident tooling remains an adapter around the control plane rather than part of
its ontology.
