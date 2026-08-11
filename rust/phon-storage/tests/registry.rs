use phon_schema::{Schema, SchemaId, SchemaKind};
use phon_storage::compact::{CompactError, Registry};

#[test]
fn aligned_registry_rejects_a_stated_id_that_does_not_match_content() {
    let schema = Schema {
        id: SchemaId::from_raw(7),
        type_params: Vec::new(),
        kind: SchemaKind::Struct {
            name: "Empty".into(),
            fields: Vec::new(),
        },
    };
    assert!(matches!(
        Registry::try_new([schema]),
        Err(CompactError::BundleSchemaIdMismatch { .. })
    ));
}
