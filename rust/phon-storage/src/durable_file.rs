use std::collections::HashMap;

use blake3::Hash;
use phon_schema::{
    DecodeError, SchemaBundle, SchemaBundleLimits, SchemaId, SchemaRef, schema_bundle_from_bytes,
    schema_bundle_to_bytes,
};

const MAGIC: &[u8; 8] = b"PHONFIL1";
const FORMAT: u32 = 1;
const ALIGNMENT: u64 = 16;
const FIXED_HEADER: usize = 32;
const DESCRIPTOR_SIZE: usize = 72;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableFileError {
    OffsetOverflow,
    FileLength {
        declared: u64,
        actual: usize,
    },
    InvalidMagic,
    UnsupportedFormat(u32),
    InvalidDescriptor,
    MisalignedExtent {
        extent: usize,
        offset: u64,
    },
    NonMinimalPlacement {
        extent: usize,
        expected: u64,
        actual: u64,
    },
    TruncatedExtent {
        extent: usize,
        offset: u64,
        len: u64,
        file_len: usize,
    },
    RegionSchemaMismatch {
        region: u32,
        expected: SchemaRef,
        actual: SchemaRef,
        encoded_offset: u64,
    },
    UnreachableRegion {
        region: u32,
    },
    DuplicateRegionReachability {
        region: u32,
        first_offset: u64,
        second_offset: u64,
    },
    DanglingRegionReference {
        region: u32,
        encoded_offset: u64,
    },
    NonRepeatable {
        extent: usize,
    },
    SchemaBundle(DecodeError),
    MissingSchema(SchemaId),
    WriteFailed {
        written: u64,
        kind: std::io::ErrorKind,
    },
}
impl core::fmt::Display for DurableFileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "durable PHON file error: {self:?}")
    }
}
impl std::error::Error for DurableFileError {}
type Result<T> = core::result::Result<T, DurableFileError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionRefOccurrence {
    pub source_region: Option<u32>,
    pub target_region: u32,
    pub target_schema: SchemaRef,
    pub encoded_offset: u64,
}
#[derive(Clone, Debug)]
enum PayloadSource {
    Repeatable(Vec<u8>),
    Sequence(Vec<Vec<u8>>),
}
#[derive(Clone, Debug)]
pub struct ExtentPayload {
    schema: SchemaRef,
    source: PayloadSource,
}
impl ExtentPayload {
    #[must_use]
    pub fn repeatable(schema: SchemaRef, bytes: Vec<u8>) -> Self {
        Self {
            schema,
            source: PayloadSource::Repeatable(bytes),
        }
    }
    #[must_use]
    pub fn non_repeatable(schema: SchemaRef, passes: Vec<Vec<u8>>) -> Self {
        Self {
            schema,
            source: PayloadSource::Sequence(passes),
        }
    }
    fn pass(&self, pass: usize) -> &[u8] {
        match &self.source {
            PayloadSource::Repeatable(bytes) => bytes,
            PayloadSource::Sequence(passes) => passes
                .get(pass)
                .or_else(|| passes.last())
                .map_or(&[], Vec::as_slice),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DurableFilePlan {
    schemas: SchemaBundle,
    root: ExtentPayload,
    regions: Vec<ExtentPayload>,
    region_refs: Vec<RegionRefOccurrence>,
}
impl DurableFilePlan {
    #[must_use]
    pub fn new(
        schemas: SchemaBundle,
        root: ExtentPayload,
        regions: Vec<ExtentPayload>,
        region_refs: Vec<RegionRefOccurrence>,
    ) -> Self {
        Self {
            schemas,
            root,
            regions,
            region_refs,
        }
    }
    #[must_use]
    pub fn region_refs(&self) -> &[RegionRefOccurrence] {
        &self.region_refs
    }
    pub fn region_refs_mut(&mut self) -> &mut Vec<RegionRefOccurrence> {
        &mut self.region_refs
    }
    pub fn write_to_vec(&self) -> Result<Vec<u8>> {
        self.validate_graph()?;
        let schema_bytes = schema_bundle_to_bytes(self.schemas.schemas())
            .map_err(DurableFileError::SchemaBundle)?;
        let mut payloads = Vec::with_capacity(self.regions.len() + 2);
        payloads.push((schema_bytes.as_slice(), None));
        payloads.push((self.root.pass(0), Some(&self.root.schema)));
        for region in &self.regions {
            payloads.push((region.pass(0), Some(&region.schema)));
        }
        let descriptor_bytes = payloads
            .len()
            .checked_mul(DESCRIPTOR_SIZE)
            .ok_or(DurableFileError::OffsetOverflow)?;
        let envelope_len = FIXED_HEADER
            .checked_add(descriptor_bytes)
            .ok_or(DurableFileError::OffsetOverflow)? as u64;
        let mut offsets = Vec::with_capacity(payloads.len());
        let mut cursor = align_up(envelope_len, ALIGNMENT)?;
        for (index, (bytes, _)) in payloads.iter().enumerate() {
            offsets.push(cursor);
            cursor = cursor
                .checked_add(bytes.len() as u64)
                .ok_or(DurableFileError::OffsetOverflow)?;
            if index + 1 < payloads.len() {
                cursor = align_up(cursor, ALIGNMENT)?;
            }
        }
        let file_len = cursor;
        let capacity = usize::try_from(file_len).map_err(|_| DurableFileError::OffsetOverflow)?;
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT.to_le_bytes());
        out.extend_from_slice(&(payloads.len() as u32).to_le_bytes());
        out.extend_from_slice(&file_len.to_le_bytes());
        out.extend_from_slice(&(FIXED_HEADER as u64).to_le_bytes());
        for (index, ((bytes, schema), offset)) in payloads.iter().zip(&offsets).enumerate() {
            let kind = if index == 0 {
                0
            } else if index == 1 {
                1
            } else {
                2
            };
            out.extend_from_slice(&(kind as u32).to_le_bytes());
            out.extend_from_slice(&((index.saturating_sub(2)) as u32).to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&ALIGNMENT.to_le_bytes());
            encode_schema_slot(&mut out, *schema)?;
            out.extend_from_slice(blake3::hash(bytes).as_bytes());
        }
        pad(&mut out, ALIGNMENT as usize);
        for (index, (expected, _)) in payloads.iter().enumerate() {
            let actual = if index == 0 {
                schema_bytes.as_slice()
            } else if index == 1 {
                self.root.pass(1)
            } else {
                self.regions[index - 2].pass(1)
            };
            if actual.len() != expected.len() || blake3::hash(actual) != blake3::hash(expected) {
                return Err(DurableFileError::NonRepeatable { extent: index });
            }
            out.extend_from_slice(actual);
            if index + 1 < payloads.len() {
                pad(&mut out, ALIGNMENT as usize);
            }
        }
        debug_assert_eq!(out.len(), capacity);
        Ok(out)
    }
    pub fn write_to(&self, sink: &mut impl std::io::Write) -> Result<()> {
        let bytes = self.write_to_vec()?;
        let mut written = 0usize;
        while written < bytes.len() {
            match sink.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(DurableFileError::WriteFailed {
                        written: written as u64,
                        kind: std::io::ErrorKind::WriteZero,
                    });
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(DurableFileError::WriteFailed {
                        written: written as u64,
                        kind: error.kind(),
                    });
                }
            }
        }
        sink.flush().map_err(|error| DurableFileError::WriteFailed {
            written: written as u64,
            kind: error.kind(),
        })
    }
    fn validate_graph(&self) -> Result<()> {
        validate_region_graph(
            &self
                .regions
                .iter()
                .map(|r| r.schema.clone())
                .collect::<Vec<_>>(),
            &self.region_refs,
        )
    }
}
fn validate_region_graph(regions: &[SchemaRef], refs: &[RegionRefOccurrence]) -> Result<()> {
    let mut seen: HashMap<u32, u64> = HashMap::new();
    for reference in refs {
        let Some(actual) = regions.get(reference.target_region as usize) else {
            return Err(DurableFileError::DanglingRegionReference {
                region: reference.target_region,
                encoded_offset: reference.encoded_offset,
            });
        };
        if actual != &reference.target_schema {
            return Err(DurableFileError::RegionSchemaMismatch {
                region: reference.target_region,
                expected: actual.clone(),
                actual: reference.target_schema.clone(),
                encoded_offset: reference.encoded_offset,
            });
        }
        if let Some(first) = seen.insert(reference.target_region, reference.encoded_offset) {
            return Err(DurableFileError::DuplicateRegionReachability {
                region: reference.target_region,
                first_offset: first,
                second_offset: reference.encoded_offset,
            });
        }
    }
    for region in 0..regions.len() as u32 {
        if !seen.contains_key(&region) {
            return Err(DurableFileError::UnreachableRegion { region });
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ExtentDescriptor {
    index: usize,
    descriptor_offset: usize,
    kind: u32,
    number: u32,
    offset: u64,
    len: u64,
    schema: Option<SchemaRef>,
    digest: Hash,
}
impl ExtentDescriptor {
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset + self.len
    }
    pub fn patch_offset(&self, bytes: &mut [u8], offset: u64) {
        bytes[self.descriptor_offset + 8..self.descriptor_offset + 16]
            .copy_from_slice(&offset.to_le_bytes())
    }
}
pub struct ExtentView<'a> {
    descriptor: &'a ExtentDescriptor,
    bytes: &'a [u8],
}
impl<'a> ExtentView<'a> {
    #[must_use]
    pub fn schema(&self) -> &SchemaRef {
        self.descriptor.schema.as_ref().expect("typed extent")
    }
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    #[must_use]
    pub fn extent(&self) -> &ExtentDescriptor {
        self.descriptor
    }
}
pub struct StructuralFileView<'a> {
    schemas: SchemaBundle,
    bytes: &'a [u8],
    extents: Vec<ExtentDescriptor>,
}
impl<'a> StructuralFileView<'a> {
    pub fn parse(bytes: &'a [u8], refs: &[RegionRefOccurrence]) -> Result<Self> {
        if bytes.len() < FIXED_HEADER {
            return Err(DurableFileError::FileLength {
                declared: FIXED_HEADER as u64,
                actual: bytes.len(),
            });
        }
        if &bytes[..8] != MAGIC {
            return Err(DurableFileError::InvalidMagic);
        }
        let format = u32_at(bytes, 8)?;
        if format != FORMAT {
            return Err(DurableFileError::UnsupportedFormat(format));
        }
        let count = u32_at(bytes, 12)? as usize;
        let file_len = u64_at(bytes, 16)?;
        if file_len != bytes.len() as u64 {
            return Err(DurableFileError::FileLength {
                declared: file_len,
                actual: bytes.len(),
            });
        }
        let descriptor_end = FIXED_HEADER
            .checked_add(
                count
                    .checked_mul(DESCRIPTOR_SIZE)
                    .ok_or(DurableFileError::OffsetOverflow)?,
            )
            .ok_or(DurableFileError::OffsetOverflow)?;
        if descriptor_end > bytes.len() {
            return Err(DurableFileError::TruncatedExtent {
                extent: 0,
                offset: 0,
                len: descriptor_end as u64,
                file_len: bytes.len(),
            });
        }

        let mut extents = Vec::with_capacity(count);
        for index in 0..count {
            let base = FIXED_HEADER + index * DESCRIPTOR_SIZE;
            let kind = u32_at(bytes, base)?;
            let number = u32_at(bytes, base + 4)?;
            let offset = u64_at(bytes, base + 8)?;
            let len = u64_at(bytes, base + 16)?;
            let alignment = u64_at(bytes, base + 24)?;
            if alignment != ALIGNMENT || !offset.is_multiple_of(ALIGNMENT) {
                return Err(DurableFileError::MisalignedExtent {
                    extent: index,
                    offset,
                });
            }
            let schema = decode_schema_slot(&bytes[base + 32..base + 40])?;
            let digest = Hash::from_bytes(bytes[base + 40..base + 72].try_into().unwrap());
            extents.push(ExtentDescriptor {
                index,
                descriptor_offset: base,
                kind,
                number,
                offset,
                len,
                schema,
                digest,
            });
        }

        let mut expected = align_up(descriptor_end as u64, ALIGNMENT)?;
        for extent in &extents {
            if extent.offset != expected {
                return Err(DurableFileError::NonMinimalPlacement {
                    extent: extent.index,
                    expected,
                    actual: extent.offset,
                });
            }
            let end = extent
                .offset
                .checked_add(extent.len)
                .ok_or(DurableFileError::OffsetOverflow)?;
            if end > file_len {
                return Err(DurableFileError::TruncatedExtent {
                    extent: extent.index,
                    offset: extent.offset,
                    len: extent.len,
                    file_len: bytes.len(),
                });
            }
            let actual = &bytes[extent.offset as usize..end as usize];
            if blake3::hash(actual) != extent.digest {
                return Err(DurableFileError::InvalidDescriptor);
            }
            expected = if extent.index + 1 < extents.len() {
                align_up(end, ALIGNMENT)?
            } else {
                end
            };
        }
        if expected != file_len {
            return Err(DurableFileError::FileLength {
                declared: expected,
                actual: bytes.len(),
            });
        }
        if extents.len() < 2 || extents[0].kind != 0 || extents[1].kind != 1 {
            return Err(DurableFileError::InvalidDescriptor);
        }
        for (index, extent) in extents.iter().enumerate().skip(2) {
            if extent.kind != 2 || extent.number as usize != index - 2 {
                return Err(DurableFileError::InvalidDescriptor);
            }
        }

        let schema_extent = &extents[0];
        let schemas = schema_bundle_from_bytes(
            &bytes[schema_extent.offset as usize..schema_extent.end() as usize],
            SchemaBundleLimits::default(),
        )
        .map_err(DurableFileError::SchemaBundle)?;
        validate_extent_schema(&extents[1], &schemas)?;
        for extent in extents.iter().skip(2) {
            validate_extent_schema(extent, &schemas)?;
        }
        let regions = extents
            .iter()
            .skip(2)
            .map(|extent| {
                extent
                    .schema
                    .clone()
                    .ok_or(DurableFileError::InvalidDescriptor)
            })
            .collect::<Result<Vec<_>>>()?;
        validate_region_graph(&regions, refs)?;
        Ok(Self {
            schemas,
            bytes,
            extents,
        })
    }
    #[must_use]
    pub fn extents(&self) -> &[ExtentDescriptor] {
        &self.extents
    }
    #[must_use]
    pub fn schemas(&self) -> &SchemaBundle {
        &self.schemas
    }
    #[must_use]
    pub fn root_schema(&self) -> &SchemaRef {
        self.extents[1].schema.as_ref().expect("root schema")
    }
    #[must_use]
    pub fn root(&self) -> ExtentView<'_> {
        self.view(1)
    }
    pub fn region(&self, number: u32) -> Option<ExtentView<'_>> {
        self.extents
            .get(number as usize + 2)
            .map(|_| self.view(number as usize + 2))
    }
    fn view(&self, index: usize) -> ExtentView<'_> {
        let descriptor = &self.extents[index];
        let start = descriptor.offset as usize;
        ExtentView {
            descriptor,
            bytes: &self.bytes[start..start + descriptor.len as usize],
        }
    }
}

fn validate_extent_schema(extent: &ExtentDescriptor, schemas: &SchemaBundle) -> Result<()> {
    let Some(SchemaRef::Concrete { id, args }) = extent.schema.as_ref() else {
        return Err(DurableFileError::InvalidDescriptor);
    };
    if !args.is_empty() {
        return Err(DurableFileError::InvalidDescriptor);
    }
    let primitive = phon_schema::Primitive::ALL
        .iter()
        .any(|primitive| phon_schema::primitive_id(*primitive) == *id);
    if !primitive && !schemas.schemas().iter().any(|schema| schema.id == *id) {
        return Err(DurableFileError::MissingSchema(*id));
    }
    Ok(())
}
pub fn align_up(value: u64, alignment: u64) -> Result<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(DurableFileError::InvalidDescriptor);
    }
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .ok_or(DurableFileError::OffsetOverflow)
}
fn pad(bytes: &mut Vec<u8>, alignment: usize) {
    while !bytes.len().is_multiple_of(alignment) {
        bytes.push(0)
    }
}
fn encode_schema_slot(out: &mut Vec<u8>, schema: Option<&SchemaRef>) -> Result<()> {
    match schema {
        None => out.extend_from_slice(&0u64.to_le_bytes()),
        Some(SchemaRef::Concrete { id, args }) if args.is_empty() => {
            out.extend_from_slice(&id.as_u64().to_le_bytes())
        }
        Some(_) => return Err(DurableFileError::InvalidDescriptor),
    }
    Ok(())
}
fn decode_schema_slot(bytes: &[u8]) -> Result<Option<SchemaRef>> {
    let raw = u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| DurableFileError::InvalidDescriptor)?,
    );
    if raw == 0 {
        Ok(None)
    } else {
        Ok(Some(SchemaRef::concrete(SchemaId::from_raw(raw))))
    }
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(DurableFileError::InvalidDescriptor)?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(DurableFileError::InvalidDescriptor)?
            .try_into()
            .unwrap(),
    ))
}
