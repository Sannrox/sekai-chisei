//! Downstream embedders must keep compiling when the contract grows a unary
//! RPC. Generated default stubs return UNIMPLEMENTED for omitted methods.

use sekai_proto::chisei::chisei_service_server::ChiseiService;
use sekai_proto::sekai::sekai_service_server::SekaiService;
use sekai_proto::sekai::{ListSiteAgentWorkingMemoryRequest, ListSiteAgentWorkingMemoryResponse};

struct DownstreamEmbedder;

#[tonic::async_trait]
impl SekaiService for DownstreamEmbedder {}

#[tonic::async_trait]
impl ChiseiService for DownstreamEmbedder {}

#[test]
fn a_partial_service_impl_compiles_without_new_rpcs() {
    fn bind<T: SekaiService + ChiseiService>(_: T) {}
    bind(DownstreamEmbedder);
}

#[test]
fn generated_messages_are_built_with_default_fru() {
    let request = ListSiteAgentWorkingMemoryRequest {
        namespace: "ops".into(),
        ..Default::default()
    };
    let response = ListSiteAgentWorkingMemoryResponse::default();
    assert_eq!(request.namespace, "ops");
    assert!(response.items.is_empty());
}
