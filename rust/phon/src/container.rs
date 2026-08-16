use std::borrow::Cow;
use std::fmt;

use facet::Facet;
use facet_phon::Codec;
use phon_schema::SchemaId;

const HEADER_SIZE: usize = 64;
const DIRECTORY_ALIGNMENT: usize = 8;
const ENCODING_RAW: u8 = 0;
const ENCODING_PHON: u8 = 1;

#[derive(Clone, Copy, Debug)]
pub struct ContainerLimits {
    pub max_directory_bytes: usize,
    pub max_sections: usize,
}

impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            max_directory_bytes: 16 * 1024 * 1024,
            max_sections: 1 << 16,
        }
    }
}

#[derive(Debug)]
pub enum ContainerError {
    BadMagic,
    UnsupportedVersion {
        major: u16,
        minor: u16,
    },
    Truncated {
        needed: usize,
        actual: usize,
    },
    MalformedHeader,
    MalformedDirectory,
    LimitExceeded,
    SizeOverflow,
    SectionOutOfBounds,
    InvalidAlignment,
    NonCanonicalPadding,
    IntegrityMismatch {
        expected: [u8; 16],
        actual: [u8; 16],
    },
    FacetPhon(facet_phon::Error),
}

impl fmt::Display for ContainerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PHON container error: {self:?}")
    }
}

impl std::error::Error for ContainerError {}

impl From<facet_phon::Error> for ContainerError {
    fn from(error: facet_phon::Error) -> Self {
        Self::FacetPhon(error)
    }
}

pub struct SectionInput<'a> {
    name: String,
    kind: u32,
    schema_id: Option<SchemaId>,
    alignment: u32,
    flags: u32,
    bytes: Cow<'a, [u8]>,
}

impl<'a> SectionInput<'a> {
    pub fn raw(
        name: impl Into<String>,
        kind: u32,
        alignment: u32,
        flags: u32,
        bytes: &'a [u8],
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            schema_id: None,
            alignment,
            flags,
            bytes: Cow::Borrowed(bytes),
        }
    }

    pub fn phon(
        name: impl Into<String>,
        kind: u32,
        schema_id: SchemaId,
        alignment: u32,
        flags: u32,
        bytes: &'a [u8],
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            schema_id: Some(schema_id),
            alignment,
            flags,
            bytes: Cow::Borrowed(bytes),
        }
    }

    pub fn raw_owned(
        name: impl Into<String>,
        kind: u32,
        alignment: u32,
        flags: u32,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            schema_id: None,
            alignment,
            flags,
            bytes: Cow::Owned(bytes),
        }
    }

    pub fn phon_owned(
        name: impl Into<String>,
        kind: u32,
        schema_id: SchemaId,
        alignment: u32,
        flags: u32,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            schema_id: Some(schema_id),
            alignment,
            flags,
            bytes: Cow::Owned(bytes),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionDescriptor {
    name: String,
    kind: u32,
    offset: u64,
    encoded_len: u64,
    alignment: u32,
    schema_id: Option<SchemaId>,
    flags: u32,
}

impl SectionDescriptor {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn kind(&self) -> u32 {
        self.kind
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn encoded_len(&self) -> u64 {
        self.encoded_len
    }

    pub const fn alignment(&self) -> u32 {
        self.alignment
    }

    pub const fn schema_id(&self) -> Option<SchemaId> {
        self.schema_id
    }

    pub const fn flags(&self) -> u32 {
        self.flags
    }
}

pub struct Section<'a> {
    descriptor: &'a SectionDescriptor,
    bytes: &'a [u8],
}

impl Section<'_> {
    pub const fn descriptor(&self) -> &SectionDescriptor {
        self.descriptor
    }

    pub fn name(&self) -> &str {
        self.descriptor.name()
    }

    pub const fn kind(&self) -> u32 {
        self.descriptor.kind()
    }

    pub const fn schema_id(&self) -> Option<SchemaId> {
        self.descriptor.schema_id()
    }

    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

pub struct Container<'a> {
    bytes: &'a [u8],
    major: u16,
    minor: u16,
    identity: [u8; 16],
    sections: Vec<SectionDescriptor>,
    directory_end: usize,
}

impl<'a> Container<'a> {
    pub fn parse(
        bytes: &'a [u8],
        magic: [u8; 8],
        expected_major: u16,
        expected_minor: u16,
        limits: ContainerLimits,
    ) -> Result<Self, ContainerError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ContainerError::Truncated {
                needed: HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        if bytes[..8] != magic {
            return Err(ContainerError::BadMagic);
        }
        let major = read_u16(bytes, 8)?;
        let minor = read_u16(bytes, 10)?;
        if major != expected_major || minor != expected_minor {
            return Err(ContainerError::UnsupportedVersion { major, minor });
        }
        if bytes[12] != 1 || bytes[13..16] != [0; 3] {
            return Err(ContainerError::MalformedHeader);
        }
        let file_len = usize_from_u64(read_u64(bytes, 16)?)?;
        if file_len != bytes.len() {
            return Err(ContainerError::Truncated {
                needed: file_len,
                actual: bytes.len(),
            });
        }
        let directory_offset = usize_from_u64(read_u64(bytes, 24)?)?;
        let directory_len = usize_from_u64(read_u64(bytes, 32)?)?;
        if directory_offset != HEADER_SIZE || read_u32(bytes, 40)? as usize != DIRECTORY_ALIGNMENT {
            return Err(ContainerError::MalformedHeader);
        }
        if directory_len > limits.max_directory_bytes {
            return Err(ContainerError::LimitExceeded);
        }
        let directory_end = directory_offset
            .checked_add(directory_len)
            .ok_or(ContainerError::SizeOverflow)?;
        let directory_bytes = bytes
            .get(directory_offset..directory_end)
            .ok_or(ContainerError::SectionOutOfBounds)?;
        let expected: [u8; 16] = bytes[48..64].try_into().expect("fixed header");
        let actual = identity(&bytes[HEADER_SIZE..]);
        if expected != actual {
            return Err(ContainerError::IntegrityMismatch { expected, actual });
        }
        let sections = decode_directory(directory_bytes, limits.max_sections)?;
        if encode_directory(&sections)? != directory_bytes {
            return Err(ContainerError::MalformedDirectory);
        }
        validate_sections(bytes, directory_end, &sections)?;
        Ok(Self {
            bytes,
            major,
            minor,
            identity: expected,
            sections,
            directory_end,
        })
    }

    pub const fn version(&self) -> (u16, u16) {
        (self.major, self.minor)
    }

    pub fn sections(&self) -> &[SectionDescriptor] {
        &self.sections
    }

    pub const fn directory_end(&self) -> usize {
        self.directory_end
    }

    pub const fn identity(&self) -> [u8; 16] {
        self.identity
    }

    pub fn section(&self, kind: u32) -> Option<Section<'_>> {
        let descriptor = self.sections.iter().find(|section| section.kind == kind)?;
        let start = usize::try_from(descriptor.offset).ok()?;
        let len = usize::try_from(descriptor.encoded_len).ok()?;
        Some(Section {
            descriptor,
            bytes: self.bytes.get(start..start.checked_add(len)?)?,
        })
    }
}

pub struct ContainerWriter<'a> {
    magic: [u8; 8],
    major: u16,
    minor: u16,
    sections: Vec<SectionInput<'a>>,
}

impl<'a> ContainerWriter<'a> {
    pub fn new(magic: [u8; 8], major: u16, minor: u16) -> Self {
        Self {
            magic,
            major,
            minor,
            sections: Vec::new(),
        }
    }

    pub fn from_container(container: &'a Container<'a>) -> Self {
        let sections = container
            .sections
            .iter()
            .map(|descriptor| {
                let bytes = container
                    .section(descriptor.kind)
                    .expect("validated section")
                    .bytes;
                SectionInput {
                    name: descriptor.name.clone(),
                    kind: descriptor.kind,
                    schema_id: descriptor.schema_id,
                    alignment: descriptor.alignment,
                    flags: descriptor.flags,
                    bytes: Cow::Borrowed(bytes),
                }
            })
            .collect();
        Self {
            magic: container.bytes[..8].try_into().expect("validated magic"),
            major: container.major,
            minor: container.minor,
            sections,
        }
    }

    pub fn section(mut self, section: SectionInput<'a>) -> Self {
        self.sections.push(section);
        self
    }

    pub fn encode(self) -> Result<Vec<u8>, ContainerError> {
        validate_inputs(&self.sections)?;
        let mut descriptors = self
            .sections
            .iter()
            .map(|section| SectionDescriptor {
                name: section.name.clone(),
                kind: section.kind,
                offset: 0,
                encoded_len: section.bytes.len() as u64,
                alignment: section.alignment,
                schema_id: section.schema_id,
                flags: section.flags,
            })
            .collect::<Vec<_>>();
        let mut directory = encode_directory(&descriptors)?;
        loop {
            let mut cursor = align_up(HEADER_SIZE + directory.len(), DIRECTORY_ALIGNMENT)?;
            for (descriptor, section) in descriptors.iter_mut().zip(&self.sections) {
                cursor = align_up(cursor, section.alignment as usize)?;
                descriptor.offset = cursor as u64;
                cursor = cursor
                    .checked_add(section.bytes.len())
                    .ok_or(ContainerError::SizeOverflow)?;
            }
            let updated = encode_directory(&descriptors)?;
            if updated.len() == directory.len() {
                directory = updated;
                break;
            }
            directory = updated;
        }
        let file_len = descriptors
            .last()
            .map(|descriptor| {
                usize_from_u64(descriptor.offset)?
                    .checked_add(
                        usize::try_from(descriptor.encoded_len)
                            .map_err(|_| ContainerError::SizeOverflow)?,
                    )
                    .ok_or(ContainerError::SizeOverflow)
            })
            .transpose()?
            .unwrap_or_else(|| HEADER_SIZE + directory.len());
        let mut bytes = vec![0; file_len];
        bytes[..8].copy_from_slice(&self.magic);
        bytes[8..10].copy_from_slice(&self.major.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.minor.to_le_bytes());
        bytes[12] = 1;
        bytes[16..24].copy_from_slice(&(file_len as u64).to_le_bytes());
        bytes[24..32].copy_from_slice(&(HEADER_SIZE as u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(directory.len() as u64).to_le_bytes());
        bytes[40..44].copy_from_slice(&(DIRECTORY_ALIGNMENT as u32).to_le_bytes());
        bytes[HEADER_SIZE..HEADER_SIZE + directory.len()].copy_from_slice(&directory);
        for (descriptor, section) in descriptors.iter().zip(self.sections) {
            let start = descriptor.offset as usize;
            bytes[start..start + section.bytes.len()].copy_from_slice(&section.bytes);
        }
        let digest = identity(&bytes[HEADER_SIZE..]);
        bytes[48..64].copy_from_slice(&digest);
        Ok(bytes)
    }
}

fn validate_inputs(sections: &[SectionInput<'_>]) -> Result<(), ContainerError> {
    for (index, section) in sections.iter().enumerate() {
        if section.kind == 0
            || section.name.is_empty()
            || section.alignment == 0
            || !section.alignment.is_power_of_two()
            || sections[..index]
                .iter()
                .any(|candidate| candidate.kind == section.kind || candidate.name == section.name)
        {
            return Err(ContainerError::MalformedDirectory);
        }
    }
    Ok(())
}

fn validate_sections(
    bytes: &[u8],
    directory_end: usize,
    sections: &[SectionDescriptor],
) -> Result<(), ContainerError> {
    let mut previous_end = directory_end;
    for (index, section) in sections.iter().enumerate() {
        if section.kind == 0
            || section.name.is_empty()
            || sections[..index]
                .iter()
                .any(|candidate| candidate.kind == section.kind || candidate.name == section.name)
        {
            return Err(ContainerError::MalformedDirectory);
        }
        if section.alignment == 0 || !section.alignment.is_power_of_two() {
            return Err(ContainerError::InvalidAlignment);
        }
        let start = usize_from_u64(section.offset)?;
        let len = usize_from_u64(section.encoded_len)?;
        let end = start.checked_add(len).ok_or(ContainerError::SizeOverflow)?;
        let expected_start = align_up(previous_end, section.alignment as usize)?;
        if start != expected_start || end > bytes.len() {
            return Err(ContainerError::SectionOutOfBounds);
        }
        if bytes[previous_end..start].iter().any(|byte| *byte != 0) {
            return Err(ContainerError::NonCanonicalPadding);
        }
        previous_end = end;
    }
    if bytes[previous_end..].iter().any(|byte| *byte != 0) {
        return Err(ContainerError::NonCanonicalPadding);
    }
    Ok(())
}

#[derive(Facet)]
struct Directory {
    sections: Vec<DirectorySection>,
}

#[derive(Facet)]
struct DirectorySection {
    name: String,
    kind: u32,
    offset: u64,
    encoded_len: u64,
    alignment: u32,
    encoding: u8,
    schema_id: u64,
    flags: u32,
}

fn encode_directory(sections: &[SectionDescriptor]) -> Result<Vec<u8>, ContainerError> {
    let directory = Directory {
        sections: sections
            .iter()
            .map(|section| DirectorySection {
                name: section.name.clone(),
                kind: section.kind,
                offset: section.offset,
                encoded_len: section.encoded_len,
                alignment: section.alignment,
                encoding: if section.schema_id.is_some() {
                    ENCODING_PHON
                } else {
                    ENCODING_RAW
                },
                schema_id: section.schema_id.map_or(0, SchemaId::as_u64),
                flags: section.flags,
            })
            .collect(),
    };
    Codec::<Directory>::new()?
        .encode(&directory)
        .map_err(Into::into)
}

fn decode_directory(
    bytes: &[u8],
    max_sections: usize,
) -> Result<Vec<SectionDescriptor>, ContainerError> {
    let directory = Codec::<Directory>::new()?.decode(bytes)?;
    if directory.sections.len() > max_sections {
        return Err(ContainerError::LimitExceeded);
    }
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(directory.sections.len())
        .map_err(|_| ContainerError::LimitExceeded)?;
    for section in directory.sections {
        let schema_id = match section.encoding {
            ENCODING_RAW if section.schema_id == 0 => None,
            ENCODING_PHON => Some(SchemaId::from_raw(section.schema_id)),
            _ => return Err(ContainerError::MalformedDirectory),
        };
        sections.push(SectionDescriptor {
            name: section.name,
            kind: section.kind,
            offset: section.offset,
            encoded_len: section.encoded_len,
            alignment: section.alignment,
            schema_id,
            flags: section.flags,
        });
    }
    Ok(sections)
}

fn identity(bytes: &[u8]) -> [u8; 16] {
    blake3::hash(bytes).as_bytes()[..16]
        .try_into()
        .expect("hash length")
}

fn align_up(value: usize, alignment: usize) -> Result<usize, ContainerError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(ContainerError::SizeOverflow)
}

fn usize_from_u64(value: u64) -> Result<usize, ContainerError> {
    usize::try_from(value).map_err(|_| ContainerError::SizeOverflow)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ContainerError> {
    Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ContainerError> {
    Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ContainerError> {
    Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ContainerError> {
    let end = offset.checked_add(N).ok_or(ContainerError::SizeOverflow)?;
    bytes
        .get(offset..end)
        .ok_or(ContainerError::Truncated {
            needed: end,
            actual: bytes.len(),
        })?
        .try_into()
        .map_err(|_| ContainerError::MalformedHeader)
}
