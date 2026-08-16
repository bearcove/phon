use facet::Facet;
use facet_phon::Codec;

#[derive(Debug, Facet, PartialEq)]
struct Manifest {
    name: String,
    dialects: Vec<Dialect>,
    roots: Vec<u32>,
}

#[derive(Debug, Facet, PartialEq)]
struct Dialect {
    name: String,
    major: u16,
    minor: u16,
}

#[test]
fn facet_model_roundtrips_through_schema_driven_compact_phon() {
    let value = Manifest {
        name: "fixture".to_string(),
        dialects: vec![Dialect {
            name: "test".to_string(),
            major: 1,
            minor: 0,
        }],
        roots: vec![0, 7],
    };
    let codec = Codec::<Manifest>::new().expect("derive codec");
    let first = codec.encode(&value).expect("encode");
    assert_eq!(codec.decode(&first).expect("decode"), value);
    assert_eq!(codec.encode(&codec.decode(&first).unwrap()).unwrap(), first);
    assert!(
        codec
            .schemas()
            .iter()
            .any(|schema| schema.id == codec.root())
    );
}
