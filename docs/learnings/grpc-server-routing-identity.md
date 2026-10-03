# gRPC authentication needs server routing identity

## What happened
Scoped published-definition reads passed direct interceptor tests but failed
through a real gRPC listener with an unavailable-RPC denial.

## Root cause
The interceptor required `GrpcMethod`, which tests inserted manually. Client
extensions do not cross the wire and server interception precedes dispatch.

## Rule
Prove scoped admission through a generated client and real listener; wrap the
intercepted service with server routing identity before authentication and fencing.
