use std::fs::{File, OpenOptions};
use std::io::Write;

use facet_value::{VArray, VObject, VString, Value};
use phon_schema::{Field, Primitive, Schema, SchemaId, SchemaKind, SchemaRef, primitive_id};
use phon_storage::{AlignedDocument, AlignedError, AlignedRegistry, AlignedWriter};

const ROW_SCHEMA: SchemaId = SchemaId::from_raw(0x5eb5_1d8a_2694_b971);

fn row_schema() -> Schema {
    Schema {
        id: ROW_SCHEMA,
        type_params: Vec::new(),
        kind: SchemaKind::Struct {
            name: "Row".into(),
            fields: vec![
                Field {
                    name: "state".into(),
                    schema: SchemaRef::concrete(primitive_id(Primitive::U32)),
                    required: true,
                },
                Field {
                    name: "offset".into(),
                    schema: SchemaRef::concrete(primitive_id(Primitive::U64)),
                    required: true,
                },
                Field {
                    name: "label".into(),
                    schema: SchemaRef::concrete(primitive_id(Primitive::String)),
                    required: true,
                },
            ],
        },
    }
}

fn rows_schema() -> Schema {
    Schema {
        id: SchemaId::from_raw(0x7397_b1ad_2230_9881),
        type_params: Vec::new(),
        kind: SchemaKind::List {
            element: SchemaRef::concrete(ROW_SCHEMA),
        },
    }
}

fn row(state: u32, offset: u64, label: &str) -> Value {
    let mut row = VObject::new();
    row.insert(VString::new("state"), Value::from(state));
    row.insert(VString::new("offset"), Value::from(offset));
    row.insert(VString::new("label"), Value::from(label));
    row.into()
}

fn fixture() -> (AlignedRegistry, SchemaId, Value) {
    let rows = rows_schema();
    let root = rows.id;
    let registry = AlignedRegistry::new([row_schema(), rows]);
    let mut values = VArray::new();
    values.push(row(7, 11, "shift"));
    values.push(row(13, 17, "reduce"));
    (registry, root, values.into())
}

#[test]
fn aligned_profile_is_deterministic_and_semantically_matches_compact() {
    let (registry, root, value) = fixture();
    let first = AlignedWriter::encode(&value, root, &registry).expect("encode");
    let second = AlignedWriter::encode(&value, root, &registry).expect("encode");
    assert_eq!(first, second);

    let document = AlignedDocument::parse(&first, root, &registry).expect("parse");
    assert_eq!(document.to_value().expect("decode"), value);
    let first_row = document.root().index(0).expect("row 0");
    assert_eq!(
        first_row
            .field("state")
            .expect("state")
            .as_u32()
            .expect("u32"),
        7
    );
    assert_eq!(
        first_row
            .field("label")
            .expect("label")
            .as_str()
            .expect("str"),
        "shift"
    );
    assert!(std::ptr::eq(document.bytes().as_ptr(), first.as_ptr()));
}

#[test]
fn aligned_profile_borrows_an_mmap_without_copying() {
    let (registry, root, value) = fixture();
    let bytes = AlignedWriter::encode(&value, root, &registry).expect("encode");
    let path = std::env::temp_dir().join(format!(
        "phon-aligned-{}-{}.bin",
        std::process::id(),
        bytes.len()
    ));
    let mut file = File::create(&path).expect("create");
    file.write_all(&bytes).expect("write");
    file.sync_all().expect("sync");
    drop(file);
    let file = OpenOptions::new().read(true).open(&path).expect("open");
    // SAFETY: the test never mutates or truncates the mapped file.
    let mapping = unsafe { memmap2::MmapOptions::new().map(&file).expect("map") };
    {
        let document = AlignedDocument::parse(&mapping, root, &registry).expect("parse mmap");
        assert_eq!(
            document
                .root()
                .index(1)
                .expect("row")
                .field("offset")
                .expect("offset")
                .as_u64()
                .expect("u64"),
            17
        );
        assert!(std::ptr::eq(document.bytes().as_ptr(), mapping.as_ptr()));
    }
    drop(mapping);
    std::fs::remove_file(path).expect("remove");
}

#[test]
fn aligned_profile_rejects_wrong_schema_truncation_offsets_and_tags() {
    let (registry, root, value) = fixture();
    let bytes = AlignedWriter::encode(&value, root, &registry).expect("encode");
    assert!(matches!(
        AlignedDocument::parse(&bytes, ROW_SCHEMA, &registry),
        Err(AlignedError::WrongSchema { .. })
    ));
    assert!(matches!(
        AlignedDocument::parse(&bytes[..bytes.len() - 1], root, &registry),
        Err(AlignedError::Truncated { .. })
    ));

    let mut bad_offset = bytes.clone();
    bad_offset[phon_storage::HEADER_SIZE + 8..phon_storage::HEADER_SIZE + 16]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        AlignedDocument::parse(&bad_offset, root, &registry),
        Err(AlignedError::MisalignedReference { .. })
            | Err(AlignedError::ReferenceOutOfBounds { .. })
    ));

    let mut bad_tag = bytes;
    bad_tag[phon_storage::HEADER_SIZE] = 0xff;
    assert!(matches!(
        AlignedDocument::parse(&bad_tag, root, &registry),
        Err(AlignedError::WrongNodeKind { .. })
    ));
}
