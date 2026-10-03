//! Server routing identity must be established before tonic interception.
//!
//! Client `GrpcMethod` extensions do not cross the network. This wrapper reads
//! the actual HTTP route, never caller metadata, and preserves `NamedService`.

use std::task::{Context, Poll};
use tonic::server::NamedService;
use tower::Service;

#[derive(Clone)]
pub struct RpcIdentityService<S> {
    inner: S,
}

impl<S> RpcIdentityService<S> {
    /// Wrap the intercepted service, so authentication and restore fencing see
    /// the server route before either runs. Used for TCP and Unix listeners.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

#[derive(Clone)]
struct ServerRpcPath(String);

impl<S: NamedService> NamedService for RpcIdentityService<S> {
    const NAME: &'static str = S::NAME;
}

impl<S, B> Service<http::Request<B>> for RpcIdentityService<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        let path = request.uri().path().to_owned();
        request.extensions_mut().insert(ServerRpcPath(path));
        self.inner.call(request)
    }
}

pub(super) fn request_rpc_method<T>(request: &tonic::Request<T>) -> Option<(&str, &str)> {
    if let Some(path) = request.extensions().get::<ServerRpcPath>() {
        let (service, method) = path.0.strip_prefix('/')?.split_once('/')?;
        return (!service.is_empty() && !method.is_empty() && !method.contains('/'))
            .then_some((service, method));
    }
    // In-process callers can retain tonic's typed routing extension. Actual
    // listeners always set ServerRpcPath, which takes precedence even if invalid.
    request
        .extensions()
        .get::<tonic::GrpcMethod>()
        .map(|method| (method.service(), method.method()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_path_overrides_in_process_routing_and_ignores_metadata() {
        let mut request = tonic::Request::new(());
        request
            .extensions_mut()
            .insert(tonic::GrpcMethod::new("sekai.SekaiService", "GetObject"));
        request
            .metadata_mut()
            .insert("x-rpc-method", "GetObject".parse().unwrap());
        for path in [
            "",
            "/",
            "/sekai.SekaiService",
            "/sekai.SekaiService/",
            "/sekai.SekaiService/GetObject/extra",
        ] {
            request.extensions_mut().insert(ServerRpcPath(path.into()));
            assert!(request_rpc_method(&request).is_none());
        }
        request
            .extensions_mut()
            .insert(ServerRpcPath("/chisei.ChiseiService/GetObject".into()));
        assert_eq!(
            request_rpc_method(&request),
            Some(("chisei.ChiseiService", "GetObject"))
        );
    }
    #[tokio::test]
    async fn wrapper_uses_actual_route_for_authentication_and_mutation_fencing() {
        let inner = tower::service_fn(|request: http::Request<()>| async move {
            let request = tonic::Request::from_http(request);
            assert_eq!(
                request_rpc_method(&request),
                Some(("sekai.SekaiService", "CreateObject"))
            );
            assert!(super::super::request_is_mutating_rpc(&request));
            assert!(super::super::enterprise_namespace_rpc(
                "sekai.SekaiService",
                "CreateObject"
            ));
            assert!(!super::super::enterprise_namespace_rpc(
                "chisei.ChiseiService",
                "CreateObject"
            ));
            assert!(super::super::enterprise_namespace_rpc(
                "chisei.ChiseiService",
                "PlanExecution"
            ));
            assert!(!super::super::enterprise_namespace_rpc(
                "sekai.SekaiService",
                "PlanExecution"
            ));
            Ok::<_, std::convert::Infallible>(http::Response::new(()))
        });
        let mut request = http::Request::builder()
            .uri("/sekai.SekaiService/CreateObject")
            .header("x-rpc-method", "GetObject")
            .body(())
            .unwrap();
        request
            .extensions_mut()
            .insert(tonic::GrpcMethod::new("sekai.SekaiService", "GetObject"));
        RpcIdentityService::new(inner).call(request).await.unwrap();
    }
}
