use std::fs::{File, OpenOptions};
use std::io::Write;

use facet_value::{VArray, VObject, VString, Value};
use phon_schema::{
    Field, Primitive, Schema, SchemaId, SchemaKind, SchemaRef, primitive_id, resolve_ids,
};
use phon_storage::{AlignedRegistry, DenseRange, DenseRangeWriter};

fn fixture() -> (AlignedRegistry, SchemaId, Value) {
    let schemas = resolve_ids(vec![
        Schema {
            id: SchemaId::from_raw(1),
            type_params: Vec::new(),
            kind: SchemaKind::Struct {
                name: "DenseRow".into(),
                fields: vec![
                    Field {
                        name: "kind".into(),
                        schema: SchemaRef::concrete(primitive_id(Primitive::U8)),
                        required: true,
                    },
                    Field {
                        name: "state".into(),
                        schema: SchemaRef::concrete(primitive_id(Primitive::U32)),
                        required: true,
                    },
                ],
            },
        },
        Schema {
            id: SchemaId::from_raw(2),
            type_params: Vec::new(),
            kind: SchemaKind::List {
                element: SchemaRef::concrete(SchemaId::from_raw(1)),
            },
        },
    ]);
    let root = schemas[1].id;
    let registry = AlignedRegistry::new(schemas);
    let mut rows = VArray::new();
    for (kind, state) in [(1u8, 7u32), (3, 11)] {
        let mut row = VObject::new();
        row.insert(VString::new("kind"), Value::from(kind));
        row.insert(VString::new("state"), Value::from(state));
        rows.push(row);
    }
    (registry, root, rows.into())
}

#[test]
fn dense_profile_is_deterministic_and_borrows_mmap_payload() {
    let (registry, root, rows) = fixture();
    let first = DenseRangeWriter::encode(&rows, root, &registry).expect("encode");
    let second = DenseRangeWriter::encode(&rows, root, &registry).expect("encode");
    assert_eq!(first, second);

    let path = std::env::temp_dir().join(format!(
        "phon-dense-{}-{}.bin",
        std::process::id(),
        first.len()
    ));
    let mut file = File::create(&path).expect("create");
    file.write_all(&first).expect("write");
    file.sync_all().expect("sync");
    drop(file);

    let file = OpenOptions::new().read(true).open(&path).expect("open");
    // SAFETY: the test never mutates or truncates the mapped file.
    let mapping = unsafe { memmap2::MmapOptions::new().map(&file).expect("map") };
    let range = DenseRange::parse(&mapping, root, &registry).expect("parse mmap");
    assert_eq!(range.count(), 2);
    assert_eq!(range.typed_row(1).expect("row").u32("state").unwrap(), 11);
    let payload_offset = range.payload().as_ptr() as usize - mapping.as_ptr() as usize;
    assert_eq!(range.payload(), &mapping[payload_offset..]);
    assert!(std::ptr::eq(range.bytes().as_ptr(), mapping.as_ptr()));

    drop(mapping);
    std::fs::remove_file(path).expect("remove");
}
