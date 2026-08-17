use phon_schema::{
    Primitive, SchemaBundleLimits, SchemaRef, primitive_id, schema_bundle_from_bytes,
    schema_bundle_to_bytes,
};
use phon_storage::durable_file::{
    DurableFileError, DurableFilePlan, ExtentPayload, RegionRefOccurrence, StructuralFileView,
};

fn root_schema() -> SchemaRef {
    SchemaRef::concrete(primitive_id(Primitive::U32))
}

fn region_schema() -> SchemaRef {
    SchemaRef::concrete(primitive_id(Primitive::Bytes))
}

fn empty_bundle() -> phon_schema::SchemaBundle {
    let bytes = schema_bundle_to_bytes(&[]).unwrap();
    schema_bundle_from_bytes(&bytes, SchemaBundleLimits::default()).unwrap()
}

fn valid_plan() -> DurableFilePlan {
    DurableFilePlan::new(
        empty_bundle(),
        ExtentPayload::repeatable(root_schema(), b"\x01\0\0\0".to_vec()),
        vec![ExtentPayload::repeatable(region_schema(), b"abc".to_vec())],
        vec![RegionRefOccurrence {
            source_region: None,
            target_region: 0,
            target_schema: region_schema(),
            encoded_offset: 0,
        }],
    )
}

#[test]
fn durable_file_writer_and_reader_admit_exact_region_graph() {
    let bytes = valid_plan().write_to_vec().unwrap();
    let view = StructuralFileView::parse(&bytes, valid_plan().region_refs()).unwrap();
    assert_eq!(view.root_schema(), &root_schema());
    assert_eq!(view.region(0).unwrap().schema(), &region_schema());
    assert_eq!(view.region(0).unwrap().bytes(), b"abc");
    assert!(
        view.extents()
            .windows(2)
            .all(|pair| pair[1].offset() % 16 == 0 && pair[1].offset() >= pair[0].end())
    );
}

#[test]
fn durable_file_bytes_are_deterministic_and_golden() {
    let first = valid_plan().write_to_vec().unwrap();
    let second = valid_plan().write_to_vec().unwrap();
    assert_eq!(first, second);
    assert_eq!(
        blake3::hash(&first).to_hex().as_str(),
        "e578862d6f23095b78e822ea9f875ca02ad862db17a4aba1457d9ad093c2b894"
    );
}

#[test]
fn durable_file_forward_sink_reports_short_write_without_success() {
    struct ShortSink {
        remaining: usize,
    }
    impl std::io::Write for ShortSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let written = self.remaining.min(bytes.len());
            self.remaining -= written;
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut sink = ShortSink { remaining: 17 };
    assert!(matches!(
        valid_plan().write_to(&mut sink),
        Err(DurableFileError::WriteFailed { .. })
    ));
}

#[test]
fn durable_file_forward_sink_retries_interrupted_write() {
    struct InterruptedOnce {
        interrupted: bool,
        bytes: Vec<u8>,
    }
    impl std::io::Write for InterruptedOnce {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let expected = valid_plan().write_to_vec().unwrap();
    let mut sink = InterruptedOnce {
        interrupted: false,
        bytes: Vec::new(),
    };
    valid_plan().write_to(&mut sink).unwrap();
    assert_eq!(sink.bytes, expected);
}

#[test]
fn durable_file_rejects_wrong_schema_unreachable_and_dangling_regions() {
    let mut wrong = valid_plan();
    wrong.region_refs_mut()[0].target_schema = root_schema();
    assert!(matches!(
        wrong.write_to_vec(),
        Err(DurableFileError::RegionSchemaMismatch { region: 0, .. })
    ));

    let mut unreachable = valid_plan();
    unreachable.region_refs_mut().clear();
    assert!(matches!(
        unreachable.write_to_vec(),
        Err(DurableFileError::UnreachableRegion { region: 0 })
    ));

    let mut dangling = valid_plan();
    dangling.region_refs_mut()[0].target_region = 1;
    assert!(matches!(
        dangling.write_to_vec(),
        Err(DurableFileError::DanglingRegionReference { region: 1, .. })
    ));
}

#[test]
fn durable_file_allows_repeated_and_cyclic_region_references() {
    let mut repeated = valid_plan();
    let mut alias = repeated.region_refs()[0].clone();
    alias.encoded_offset = 4;
    repeated.region_refs_mut().push(alias);
    repeated.write_to_vec().unwrap();

    let cyclic = DurableFilePlan::new(
        empty_bundle(),
        ExtentPayload::repeatable(root_schema(), b"\0\0\0\0".to_vec()),
        vec![ExtentPayload::repeatable(region_schema(), b"abc".to_vec())],
        vec![
            RegionRefOccurrence {
                source_region: None,
                target_region: 0,
                target_schema: region_schema(),
                encoded_offset: 0,
            },
            RegionRefOccurrence {
                source_region: Some(0),
                target_region: 0,
                target_schema: region_schema(),
                encoded_offset: 1,
            },
        ],
    );
    cyclic.write_to_vec().unwrap();
}

#[test]
fn durable_file_reader_rejects_overlap_misalignment_and_truncated_target() {
    let bytes = valid_plan().write_to_vec().unwrap();
    let view = StructuralFileView::parse(&bytes, valid_plan().region_refs()).unwrap();
    let region = view.region(0).unwrap().extent().clone();

    let mut overlap = bytes.clone();
    region.patch_offset(&mut overlap, view.root().extent().offset());
    assert!(matches!(
        StructuralFileView::parse(&overlap, valid_plan().region_refs()),
        Err(DurableFileError::NonMinimalPlacement { .. })
    ));

    let mut misaligned = bytes.clone();
    region.patch_offset(&mut misaligned, region.offset() + 1);
    assert!(matches!(
        StructuralFileView::parse(&misaligned, valid_plan().region_refs()),
        Err(DurableFileError::MisalignedExtent { .. }
            | DurableFileError::NonMinimalPlacement { .. })
    ));

    assert!(matches!(
        StructuralFileView::parse(&bytes[..bytes.len() - 1], valid_plan().region_refs()),
        Err(DurableFileError::FileLength { .. } | DurableFileError::TruncatedExtent { .. })
    ));
}

#[test]
fn durable_file_writer_rejects_pass_divergence() {
    let plan = DurableFilePlan::new(
        empty_bundle(),
        ExtentPayload::non_repeatable(
            root_schema(),
            vec![b"\x01\0\0\0".to_vec(), b"\x02\0\0\0".to_vec()],
        ),
        Vec::new(),
        Vec::new(),
    );
    assert!(matches!(
        plan.write_to_vec(),
        Err(DurableFileError::NonRepeatable { extent: 1 })
    ));
}

#[test]
fn durable_file_writer_rejects_offset_overflow() {
    assert!(matches!(
        phon_storage::durable_file::align_up(u64::MAX, 16),
        Err(DurableFileError::OffsetOverflow)
    ));
}
