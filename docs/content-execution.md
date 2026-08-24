# Bounded content execution

Native integrations use the separate content contract when one operation
contains ordered text, image, audio, or document parts. The existing
`PlanExecution` and `ExecutePlanStream` text contract is unchanged. A client
that calls the content methods on an older server receives gRPC
`UNIMPLEMENTED`; content is never sent as an optional field that an old server
could silently ignore.

The wire contract is `chisei.content-execution/v1`. The Rust facade advertises
`sekai.sdk-content-execution/v1` and sends the distinct
`chisei.content.execute` capability metadata.

## Contract

`ContentPartDescriptorV1` is durable metadata:

- a stable part id and one `text`, `image`, `audio`, or `document` kind;
- a normalized, allowlisted media type;
- the exact byte length and `sha256:<64 lowercase hex>` digest;
- a credential-free opaque reference;
- source, source id, source version, and observation time provenance; and
- an `accepted`, `redacted`, or `omitted` disclosure state. Redacted and
  omitted parts require a reason.

`ResolvedContentPartV1` carries the descriptor plus text or bytes for one
authorized call. The server verifies exact descriptor identity, byte length,
digest, kind/payload agreement, count, and aggregate size before contacting a
provider. Resolved payloads use redacted debug projections and never enter
receipts, logs, provider-neutral persistence, or content plan caches.

`ContentCapabilitiesV1` binds the contract version, requested input and output
kinds, media types, opaque reference mode, streaming support, and caller
limits. Hard limits cannot be disabled:

- 32 parts;
- 8 MiB per part; and
- 16 MiB across one execution.

Operators and clients may request lower limits.

## Planning and execution

1. Put routing, namespace, budget, task, system, tool, and lineage fields in
   `ContentExecutionInputV1.execution`.
2. Leave `ExecutionInput.messages` empty. Ordered descriptors belong only in
   `content_messages`.
3. Request the `chisei.policy/v1` disclosure authority and provide the
   capability envelope. Input disclosure states are requests, not authority:
   Chisei applies current namespace, residency, provider, and egress policy
   and binds its metadata-only disclosure decision into the cached plan.
   Binary disclosure to an external provider requires an `open` namespace
   data class or an operator-designated safe provider because binary payloads
   cannot use the text leak scanner. Unclassified text is scanned after
   resolution; any block or redaction finding denies the call rather than
   mutating digest-bound content.
4. Call `PlanContentExecution`. Chisei applies the existing namespace,
   policy, routing, budget, evaluation, residency, privacy, egress, and Gunshi
   planning controls. It binds the ordered descriptor digest into a
   content-specific, principal-bound plan cache.
5. Resolve only accepted parts and call `ExecuteContentPlanStream`. Chisei
   rechecks authorization and live policy, verifies every transient payload,
   applies the leak gate to resolved text, and invokes the selected adapter.

Content plans are single-use, expire after 15 minutes, and cannot be executed
through `ExecutePlanStream`. Text plans cannot be executed through the content
method.

After policy filtering, user messages must retain an accepted part. Assistant
messages must retain an accepted part or a valid tool call. Tool-result
messages require one accepted text part and a bounded call id. Invalid or
empty provider messages fail during planning, before a single-use plan is
cached.

## Provider behavior

The canonical protocol contains no provider-specific payload types. Current
OpenAI-compatible and Anthropic adapters map accepted text and image inputs to
their typed upstream blocks. Provider profiles that do not advertise image
input fail before upstream contact. Audio and document inputs remain explicit
capability failures for current profiles; they are not coerced into text.

Provider output remains text-only. No current adapter advertises output media
because the control plane does not own an object store that could externalize
bytes into a durable reference. Adding output media requires such an owner and
a separate capability update.

Hosts retain durable payload custody and resolve opaque references immediately
before execution. References must not contain URLs, filesystem paths, query
parameters, bearer material, keys, or secrets.
