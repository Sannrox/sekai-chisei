# Kubernetes on minikube through Tenkai

Plain manifests under `deploy/kubernetes/manifests/` deploy a single-replica
StatefulSet with SQLite on a PVC, a Service, TLS from Secret `sekai-chisei-tls`,
and HTTP probes on the ops port. The product file
`deploy/kubernetes/tenkai.toml` uses the `kubernetes-inprocess` executor
(server-side apply, field manager `tenkai`, health from StatefulSet
conditions). Helm, multiple replicas, and PostgreSQL are out of scope.

The Apple `container` product at `deploy/tenkai.toml` is a separate packaging
path. Use one or the other for a given environment.

## Prerequisites

- minikube with a reachable API
- `tenkaictl` with `tenkai_executor::install()` (the usual binary)
- An environment-scoped kubeconfig **file path** (not a kubeconfig blob in
  Tenkai state). Tenkai refuses implicit in-cluster discovery for this executor.

```bash
minikube start --driver=docker
export TENKAI_SOFTWARE_EXECUTOR=kubernetes-inprocess
```

## TLS secret

Non-loopback binds require TLS. Create a certificate Secret in the Tenkai
environment namespace (the environment name is the namespace) before apply.
The manifests mount `sekai-chisei-tls` at `/tls` as `tls.crt` and `tls.key`.

```bash
# Replace `local` with the Tenkai environment name if it differs.
kubectl create namespace local --dry-run=client -o yaml | kubectl apply -f -
openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
  -keyout tls.key -out tls.crt -subj "/CN=sekai-chisei" \
  -addext "subjectAltName=DNS:sekai-chisei,DNS:sekai-chisei.local.svc,DNS:sekai-chisei.local.svc.cluster.local"
kubectl -n local create secret tls sekai-chisei-tls \
  --cert=tls.crt --key=tls.key
# Keep tls.crt if clients need SEKAI_TLS_CA. Remove tls.key.
rm tls.key
```

## Publish and apply

Point Tenkai at a kubeconfig file, then publish the Kubernetes product. Unsigned
development apply is limited to the built-in `local` environment.

```bash
tenkaictl env cluster-config set local /path/to/kubeconfig
tenkaictl publish deploy/kubernetes/tenkai.toml --allow-unsigned-development
tenkaictl promote sekai-chisei@1.4.0 stable
tenkaictl env subscribe local sekai-chisei=stable
PLAN=$(tenkaictl plan --env local | sed -n 's/^plan id: //p')
tenkaictl apply "$PLAN" \
  --allow-unapproved-development \
  --development-reason "local minikube sekai-chisei"
```

Wait until the StatefulSet is available and ops health is green:

```bash
kubectl -n local rollout status statefulset/sekai-chisei --timeout=120s
kubectl -n local get pods,svc,pvc
# From inside the cluster network, ops is HTTP on 9464; gRPC is TLS on 50051.
```

The image keeps `SEKAI_SOCKET=/data/sekai.sock` on the PVC. First boot is
UDS-only: authenticated TCP stays off until a durable principal credential
exists. After the pod is Ready, create one inside the pod, then restart so
TCP binds with TLS:

```bash
kubectl -n local exec statefulset/sekai-chisei -- \
  sekaictl admin access credential create operator
kubectl -n local rollout restart statefulset/sekai-chisei
kubectl -n local rollout status statefulset/sekai-chisei --timeout=120s
# Clients: authorization Bearer <token>, SEKAI_TLS_CA pointing at tls.crt,
# and the in-cluster Service DNS on port 50051.
```

A probe failure refuses apply health. Tenkai then restores the previous
release (expect `phase=health` and often `phase=restore` in the error). That is
the same rollback path as Tenkai's minikube dogfood: publish a version whose
image or probe cannot become Available, apply it, and confirm the prior
revision is restored.

## Tear down

```bash
tenkaictl env unsubscribe local sekai-chisei
# or remove the environment workload through the usual Tenkai uninstall path
kubectl -n local delete secret sekai-chisei-tls --ignore-not-found
```
