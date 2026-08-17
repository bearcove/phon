//! phon's wire contract — the most widely depended-on layer, with no engine and
//! no language binding.
//!
//! This crate owns everything portable about a phon schema: the schema model,
//! content-derived schema identity, the dynamic [`value`] type, and the
//! self-describing codec that bootstraps schema exchange. Every other phon crate
//! depends on this one; it depends on nothing phon-specific.
//!
//! Spec: `docs/content/spec.md` — "Type system", "Schema identity",
//! "Self-describing mode", and `r[crates.concern-separation]`.

// r[impl crates.concern-separation]
pub mod bytes;
pub mod identity;
pub mod qualified_name;
pub mod schema;
pub mod selfdescribing;

/// phon's dynamic value. In Rust this *is* `facet_value::Value`, re-exported
/// rather than wrapped — a `Dynamic` field carries one directly. The
/// self-describing codec maps the cases facet carries beyond the wire tag table
/// (null, date/time, qname, uuid) onto phon kinds.
///
/// Spec: "Value" (`r[value]`).
pub mod value {
    pub use facet_value::Value;
}

pub use bytes::{DecodeError, Reader};
pub use identity::{primitive_id, recursive_schema_ids, resolve_ids};
pub use qualified_name::{
    QualifiedName, QualifiedNameError, from_compact_bytes as qualified_name_from_compact_bytes,
    from_self_describing_bytes as qualified_name_from_self_describing_bytes,
};
pub use schema::{
    ChannelDirection, Field, Primitive, Schema, SchemaId, SchemaKind, SchemaRef, Variant,
    VariantPayload,
};
pub use selfdescribing::{
    DecodeLimits, EncodeError, extended_from_string, extended_to_string, read_value,
    schema_from_bytes, schema_matches_bytes, schema_to_bytes, value_from_bytes, value_to_bytes,
    write_value,
};
pub use value::Value;

#[cfg(test)]
mod qualified_name_tests {
    use super::*;

    #[test]
    fn qualified_name_accepts_only_canonical_revision_one_grammar() {
        for valid in [
            "org.bearcove.phon.region-ref-v1",
            "org.bearcove.weavy.bytecode-v1",
            "phon.region-ref-v1",
        ] {
            assert_eq!(QualifiedName::try_from(valid).unwrap().as_str(), valid);
        }

        for invalid in [
            "",
            "local",
            ".org.example",
            "org..example",
            "org.example.",
            "Org.example",
            "org.example_name",
            "org.-example",
            "org.example-",
            "org.example--name",
            "1org.example",
            "org.1example",
            "org.example/thing",
        ] {
            assert!(
                QualifiedName::try_from(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn qualified_name_enforces_byte_bound_and_namespace_reservations() {
        let valid = format!("org.{}", "a".repeat(QualifiedName::MAX_BYTES - 4));
        assert_eq!(valid.len(), QualifiedName::MAX_BYTES);
        assert!(QualifiedName::try_from(valid.as_str()).is_ok());

        let too_long = format!("org.{}", "a".repeat(QualifiedName::MAX_BYTES - 3));
        assert_eq!(too_long.len(), QualifiedName::MAX_BYTES + 1);
        assert!(QualifiedName::try_from(too_long.as_str()).is_err());

        assert!(QualifiedName::application("phon.private-v1").is_err());
        assert!(QualifiedName::application("org.bearcove.phon.private-v1").is_err());
        assert!(QualifiedName::application("org.example.private-v1").is_ok());
    }

    #[test]
    fn qualified_name_wire_forms_are_byte_exact() {
        let name = QualifiedName::try_from("org.example.x-v1").unwrap();
        assert_eq!(name.compact_bytes(), b"\x10\0\0\0org.example.x-v1".to_vec());
        assert_eq!(
            name.self_describing_bytes(),
            b"\x0f\x10\0\0\0org.example.x-v1".to_vec()
        );
    }

    #[test]
    fn qualified_name_decoders_reject_truncation_and_noncanonical_bytes() {
        let canonical = b"\x10\0\0\0org.example.x-v1";
        assert_eq!(
            qualified_name_from_compact_bytes(canonical)
                .unwrap()
                .as_str(),
            "org.example.x-v1"
        );
        assert_eq!(
            qualified_name_from_self_describing_bytes(b"\x0f\x10\0\0\0org.example.x-v1")
                .unwrap()
                .as_str(),
            "org.example.x-v1"
        );

        for bytes in [&canonical[..0], &canonical[..3]] {
            assert!(matches!(
                qualified_name_from_compact_bytes(bytes),
                Err(DecodeError::UnexpectedEof { .. })
            ));
        }
        assert!(matches!(
            qualified_name_from_compact_bytes(&canonical[..8]),
            Err(DecodeError::LengthTooLarge { .. })
        ));
        assert!(matches!(
            qualified_name_from_compact_bytes(b"\x0b\0\0\0Org.example"),
            Err(DecodeError::Malformed("qualified name"))
        ));
        assert!(matches!(
            qualified_name_from_self_describing_bytes(b"\x10\0\0\0\0"),
            Err(DecodeError::UnexpectedTag {
                expected: "qualified name string",
                got: 0x10
            })
        ));
    }
}
