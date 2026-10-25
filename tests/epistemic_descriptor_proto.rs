//! Proto round-trip for epistemic descriptors stays in the root crate so
//! `chisei-core` does not depend on `sekai-proto`.

use prost::Message;
use sekai_chisei::chisei::epistemic_descriptor::EPISTEMIC_DESCRIPTOR_VERSION;
use sekai_proto::chisei::{EpistemicDescriptor as PbDescriptor, MemoryContextReference};

#[test]
fn protobuf_reference_is_additive_and_round_trips_unknowns() {
    let reference = MemoryContextReference {
        memory_id: "memory-1".into(),
        memory_version: 1,
        descriptor: Some(PbDescriptor {
            contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
            origin_class: "unknown".into(),
            evidence_status: "unknown".into(),
            lifecycle_status: "unknown".into(),
            source_rows_truncated: false,
            ..Default::default()
        }),
        ..Default::default()
    };
    let encoded = reference.encode_to_vec();
    let decoded = MemoryContextReference::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.memory_id, "memory-1");
    assert_eq!(
        decoded
            .descriptor
            .as_ref()
            .map(|descriptor| descriptor.contract_version.as_str()),
        Some(EPISTEMIC_DESCRIPTOR_VERSION)
    );

    // A legacy reference with no field 8 remains valid and decodes with an
    // absent descriptor, so old producers/clients do not need a rollout.
    let legacy = MemoryContextReference {
        memory_id: "legacy".into(),
        memory_version: 1,
        ..Default::default()
    };
    let decoded_legacy = MemoryContextReference::decode(legacy.encode_to_vec().as_slice()).unwrap();
    assert!(decoded_legacy.descriptor.is_none());
}
