use prost::Message;
use sekai_proto::sekai::{LlmStep, OperatorStep, PipelineStep, pipeline_step};

// Independent pre-#1368 wire contract. Do not derive this from the current schema.
#[derive(Clone, PartialEq, Message)]
struct LegacyPipelineStep {
    #[prost(string, tag = "1")]
    op: String,
    #[prost(string, tag = "2")]
    kind: String,
    #[prost(string, tag = "3")]
    property: String,
    #[prost(string, tag = "4")]
    value: String,
    #[prost(string, tag = "5")]
    relation: String,
    #[prost(string, tag = "6")]
    dir: String,
    #[prost(string, tag = "7")]
    func: String,
    #[prost(string, tag = "8")]
    field: String,
    #[prost(string, tag = "9")]
    r#as: String,
}

#[test]
fn legacy_operator_fields_keep_their_wire_numbers_and_string_types() {
    let old = LegacyPipelineStep {
        op: "filter".into(),
        kind: "customer".into(),
        property: "status".into(),
        value: "active".into(),
        relation: "owns".into(),
        dir: "out".into(),
        func: "count".into(),
        field: "id".into(),
        r#as: "total".into(),
    };
    let current = PipelineStep::decode(old.encode_to_vec().as_slice()).unwrap();
    assert_eq!(current.op, old.op);
    assert_eq!(current.kind, old.kind);
    assert_eq!(current.property, old.property);
    assert_eq!(current.value, old.value);
    assert_eq!(current.relation, old.relation);
    assert_eq!(current.dir, old.dir);
    assert_eq!(current.func, old.func);
    assert_eq!(current.field, old.field);
    assert_eq!(current.r#as, old.r#as);
    assert!(current.step.is_none());
    assert_eq!(
        LegacyPipelineStep::decode(current.encode_to_vec().as_slice()).unwrap(),
        old
    );
}

#[test]
fn new_variants_use_unoccupied_wire_numbers() {
    for (variant, tag) in [
        (
            pipeline_step::Step::Operator(OperatorStep {
                op: "filter".into(),
                ..Default::default()
            }),
            0x52,
        ),
        (
            pipeline_step::Step::Llm(LlmStep {
                prompt_revision: "prompt/v1".into(),
                ..Default::default()
            }),
            0x5a,
        ),
    ] {
        let step = PipelineStep {
            step: Some(variant),
            ..Default::default()
        };
        let bytes = step.encode_to_vec();
        assert_eq!(bytes[0], tag);
        assert_eq!(PipelineStep::decode(bytes.as_slice()).unwrap(), step);
        assert_eq!(
            LegacyPipelineStep::decode(bytes.as_slice()).unwrap(),
            LegacyPipelineStep::default()
        );
    }
}
