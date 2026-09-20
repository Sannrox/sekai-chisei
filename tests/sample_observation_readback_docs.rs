//! Sample-observation docs must match the public Chisei proto.

fn collapsed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn sample_observation_readback_docs_match_public_proto() {
    let proto = include_str!("../proto/chisei.proto");
    assert!(
        !proto.contains("rpc RecordSampleObservation"),
        "public proto must not declare RecordSampleObservation"
    );
    assert!(
        proto.contains("rpc GetSampleObservation"),
        "public proto must declare GetSampleObservation"
    );

    let docs = include_str!("../docs/sample-observation-readback.md");
    let docs_text = collapsed(docs);
    assert!(
        docs.contains("put_sample_observation"),
        "docs must name the internal admission helper"
    );
    assert!(
        docs.contains("GetSampleObservation"),
        "docs must name the public readback RPC"
    );
    assert!(
        docs_text.contains("no public `RecordSampleObservation` RPC"),
        "docs must not present RecordSampleObservation as a public admission RPC"
    );
    assert!(
        !docs_text.contains("`RecordSampleObservation` is the authenticated admission path"),
        "docs must not describe RecordSampleObservation as the public admission path"
    );
}
