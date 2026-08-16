use phon_schema::SchemaId;
use phon_storage::container::{
    Container, ContainerError, ContainerLimits, ContainerWriter, SectionInput,
};

const MAGIC: [u8; 8] = *b"TESTCNT\0";

fn fixture() -> Vec<u8> {
    ContainerWriter::new(MAGIC, 1, 0)
        .section(SectionInput::raw("program", 4, 8, 1, b"opaque isa"))
        .section(SectionInput::phon(
            "manifest",
            2,
            SchemaId::from_raw(0x1234),
            8,
            1,
            b"typed phon",
        ))
        .encode()
        .expect("encode")
}

#[test]
fn container_roundtrips_deterministically_and_borrows_sections() {
    let first = fixture();
    let parsed = Container::parse(&first, MAGIC, 1, 0, ContainerLimits::default()).expect("parse");
    assert_eq!(parsed.version(), (1, 0));
    assert_eq!(parsed.sections().len(), 2);
    assert_eq!(parsed.section(4).expect("program").bytes(), b"opaque isa");
    assert_eq!(
        parsed.section(2).expect("manifest").schema_id(),
        Some(SchemaId::from_raw(0x1234))
    );
    let program = parsed.section(4).expect("program");
    let borrowed = program.bytes();
    assert!(borrowed.as_ptr() >= first.as_ptr());
    assert!(borrowed.as_ptr() < unsafe { first.as_ptr().add(first.len()) });
    assert_eq!(
        ContainerWriter::from_container(&parsed)
            .encode()
            .expect("reencode"),
        first
    );
}

#[test]
fn container_rejects_truncation_corruption_and_noncanonical_padding() {
    let bytes = fixture();
    for end in 0..bytes.len() {
        assert!(Container::parse(&bytes[..end], MAGIC, 1, 0, ContainerLimits::default()).is_err());
    }

    let mut corrupt = bytes.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0x80;
    assert!(matches!(
        Container::parse(&corrupt, MAGIC, 1, 0, ContainerLimits::default()),
        Err(ContainerError::IntegrityMismatch { .. })
    ));

    let parsed = Container::parse(&bytes, MAGIC, 1, 0, ContainerLimits::default()).unwrap();
    let first_offset = parsed.sections()[0].offset() as usize;
    let directory_end = parsed.directory_end();
    if directory_end < first_offset {
        let mut padded = bytes.clone();
        padded[directory_end] = 1;
        let identity = blake3::hash(&padded[64..]);
        padded[48..64].copy_from_slice(&identity.as_bytes()[..16]);
        assert!(matches!(
            Container::parse(&padded, MAGIC, 1, 0, ContainerLimits::default()),
            Err(ContainerError::NonCanonicalPadding)
        ));
    }
}

#[test]
fn container_enforces_section_count_and_directory_limits() {
    let bytes = fixture();
    assert!(matches!(
        Container::parse(
            &bytes,
            MAGIC,
            1,
            0,
            ContainerLimits {
                max_directory_bytes: 1,
                max_sections: 8,
            },
        ),
        Err(ContainerError::LimitExceeded)
    ));
    assert!(matches!(
        Container::parse(
            &bytes,
            MAGIC,
            1,
            0,
            ContainerLimits {
                max_directory_bytes: 1024 * 1024,
                max_sections: 1,
            },
        ),
        Err(ContainerError::LimitExceeded)
    ));
}

#[test]
fn every_single_byte_mutation_is_rejected_or_safely_parsed() {
    let bytes = fixture();
    for index in 0..bytes.len() {
        for mask in [1u8, 0x80] {
            let mut mutated = bytes.clone();
            mutated[index] ^= mask;
            if let Ok(container) =
                Container::parse(&mutated, MAGIC, 1, 0, ContainerLimits::default())
            {
                for descriptor in container.sections() {
                    let section = container
                        .section(descriptor.kind())
                        .expect("validated section");
                    assert_eq!(section.bytes().len() as u64, descriptor.encoded_len());
                }
            }
        }
    }
}
