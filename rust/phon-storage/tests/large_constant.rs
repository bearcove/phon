use facet_value::{VArray, VObject, VString, Value};
use phon_schema::{Field, Primitive, Schema, SchemaId, SchemaKind, SchemaRef, primitive_id};
use phon_storage::{AlignedDocument, AlignedRegistry, AlignedWriter};

const ROW: SchemaId = SchemaId::from_raw(0x1001);
const ROWS: SchemaId = SchemaId::from_raw(0x1002);

#[test]
fn million_row_constant_is_borrowed_and_randomly_addressable() {
    let row = Schema {
        id: ROW,
        type_params: Vec::new(),
        kind: SchemaKind::Struct {
            name: "LrRow".into(),
            fields: vec![
                Field {
                    name: "state".into(),
                    schema: SchemaRef::concrete(primitive_id(Primitive::U32)),
                    required: true,
                },
                Field {
                    name: "symbol".into(),
                    schema: SchemaRef::concrete(primitive_id(Primitive::U32)),
                    required: true,
                },
                Field {
                    name: "action".into(),
                    schema: SchemaRef::concrete(primitive_id(Primitive::I32)),
                    required: true,
                },
            ],
        },
    };
    let rows = Schema {
        id: ROWS,
        type_params: Vec::new(),
        kind: SchemaKind::List {
            element: SchemaRef::concrete(ROW),
        },
    };
    let registry = AlignedRegistry::new([row, rows]);
    let count = 1_000_000usize;
    let mut values = VArray::with_capacity(count);
    for index in 0..count {
        let mut value = VObject::new();
        value.insert(VString::new("state"), Value::from(index as u32));
        value.insert(VString::new("symbol"), Value::from((index % 4_096) as u32));
        value.insert(VString::new("action"), Value::from(-(index as i32)));
        values.push(value);
    }
    let values: Value = values.into();
    let bytes = AlignedWriter::encode(&values, ROWS, &registry).expect("encode");
    let document = AlignedDocument::parse(&bytes, ROWS, &registry).expect("admit");
    assert_eq!(
        document
            .root()
            .index(999_999)
            .expect("last row")
            .field("state")
            .expect("state")
            .as_u32()
            .expect("u32"),
        999_999
    );
    assert!(std::ptr::eq(document.bytes().as_ptr(), bytes.as_ptr()));
}
