//! Portable physical storage profiles for PHON values.
//!
//! The aligned profile is schema-driven like compact PHON, but gives every
//! value a stable 32-byte node and uses checked absolute offsets for child-node
//! runs and variable-width byte payloads. Nodes are explicitly encoded in
//! little endian; mapped bytes are never transmuted to Rust layouts.
pub mod compact;
use std::fmt;

use facet_value::{VArray, VBytes, VObject, VString, Value};
use phon_schema::{Primitive, SchemaId, SchemaKind, SchemaRef, VariantPayload};

const MAGIC: [u8; 8] = *b"PHONALN\0";
const VERSION: u16 = 1;
/// Size of the fixed aligned-profile header.
pub const HEADER_SIZE: usize = 64;
const NODE_SIZE: usize = 32;
const NODE_ALIGN: usize = 8;
const MAX_DEPTH: usize = 128;

const TAG_UNIT: u8 = 0;
const TAG_BOOL: u8 = 1;
const TAG_UNSIGNED: u8 = 2;
const TAG_SIGNED: u8 = 3;
const TAG_FLOAT: u8 = 4;
const TAG_CHAR: u8 = 5;
const TAG_STRING: u8 = 6;
const TAG_BYTES: u8 = 7;
const TAG_STRUCT: u8 = 8;
const TAG_TUPLE: u8 = 9;
const TAG_LIST: u8 = 10;
const TAG_OPTION_NONE: u8 = 11;
const TAG_OPTION_SOME: u8 = 12;
const TAG_ENUM: u8 = 13;

/// The validated schema registry shared by compact and aligned profiles.
pub type AlignedRegistry = compact::Registry;

fn resolve_aligned(
    registry: &AlignedRegistry,
    schema: &SchemaRef,
) -> Result<compact::Resolved, AlignedError> {
    compact::resolve(registry, schema).map_err(AlignedError::from_compact)
}

/// Deterministic encoder for the aligned PHON profile.
pub struct AlignedWriter;

impl AlignedWriter {
    pub fn encode(
        value: &Value,
        root: SchemaId,
        registry: &AlignedRegistry,
    ) -> Result<Vec<u8>, AlignedError> {
        let mut encoder = Encoder {
            bytes: vec![0; HEADER_SIZE + NODE_SIZE],
            registry,
        };
        encoder.encode_node(value, &SchemaRef::concrete(root), HEADER_SIZE, 0)?;
        let file_len = encoder.bytes.len() as u64;
        encoder.bytes[..8].copy_from_slice(&MAGIC);
        encoder.bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        encoder.bytes[10] = 1;
        encoder.bytes[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        encoder.bytes[16..24].copy_from_slice(&root.as_u64().to_le_bytes());
        encoder.bytes[24..32].copy_from_slice(&(HEADER_SIZE as u64).to_le_bytes());
        encoder.bytes[32..40].copy_from_slice(&file_len.to_le_bytes());
        Ok(encoder.bytes)
    }
}

struct Encoder<'a> {
    bytes: Vec<u8>,
    registry: &'a AlignedRegistry,
}

impl Encoder<'_> {
    fn encode_node(
        &mut self,
        value: &Value,
        schema: &SchemaRef,
        slot: usize,
        depth: usize,
    ) -> Result<(), AlignedError> {
        if depth > MAX_DEPTH {
            return Err(AlignedError::DepthExceeded);
        }
        match resolve_aligned(self.registry, schema)? {
            compact::Resolved::Primitive(primitive) => {
                self.encode_primitive(value, primitive, slot)
            }
            compact::Resolved::Composite(kind) => self.encode_kind(value, &kind, slot, depth),
        }
    }

    fn encode_primitive(
        &mut self,
        value: &Value,
        primitive: Primitive,
        slot: usize,
    ) -> Result<(), AlignedError> {
        self.bytes[slot + 1] = primitive_tag(primitive);
        match primitive {
            Primitive::Unit => {
                if !value.is_null() {
                    return Err(AlignedError::TypeMismatch("unit"));
                }
                self.bytes[slot] = TAG_UNIT;
            }
            Primitive::Bool => {
                self.bytes[slot] = TAG_BOOL;
                self.bytes[slot + 8] =
                    u8::from(value.as_bool().ok_or(AlignedError::TypeMismatch("bool"))?);
            }
            Primitive::U8 | Primitive::U16 | Primitive::U32 | Primitive::U64 | Primitive::U128 => {
                self.bytes[slot] = TAG_UNSIGNED;
                let number = value
                    .as_number()
                    .ok_or(AlignedError::TypeMismatch("unsigned number"))?;
                self.bytes[slot + 8..slot + 24]
                    .copy_from_slice(&number.to_u128().unwrap_or(0).to_le_bytes());
            }
            Primitive::I8 | Primitive::I16 | Primitive::I32 | Primitive::I64 | Primitive::I128 => {
                self.bytes[slot] = TAG_SIGNED;
                let number = value
                    .as_number()
                    .ok_or(AlignedError::TypeMismatch("signed number"))?;
                self.bytes[slot + 8..slot + 24]
                    .copy_from_slice(&number.to_i128().unwrap_or(0).to_le_bytes());
            }
            Primitive::F32 | Primitive::F64 => {
                self.bytes[slot] = TAG_FLOAT;
                let number = value
                    .as_number()
                    .ok_or(AlignedError::TypeMismatch("floating-point number"))?;
                self.bytes[slot + 8..slot + 16]
                    .copy_from_slice(&number.to_f64_lossy().to_bits().to_le_bytes());
            }
            Primitive::Char => {
                self.bytes[slot] = TAG_CHAR;
                let character = value.as_char().ok_or(AlignedError::TypeMismatch("char"))?;
                self.bytes[slot + 8..slot + 12].copy_from_slice(&(character as u32).to_le_bytes());
            }
            Primitive::String | Primitive::DateTime | Primitive::Uuid | Primitive::QName => {
                self.bytes[slot] = TAG_STRING;
                let string = value
                    .as_string()
                    .ok_or(AlignedError::TypeMismatch("string"))?;
                self.write_payload(slot, string.as_str().as_bytes())?;
            }
            Primitive::Bytes => {
                self.bytes[slot] = TAG_BYTES;
                let bytes = value
                    .as_bytes()
                    .ok_or(AlignedError::TypeMismatch("bytes"))?;
                self.write_payload(slot, bytes.as_slice())?;
            }
            Primitive::Never => return Err(AlignedError::TypeMismatch("never")),
        }
        Ok(())
    }

    fn encode_kind(
        &mut self,
        value: &Value,
        kind: &SchemaKind,
        slot: usize,
        depth: usize,
    ) -> Result<(), AlignedError> {
        match kind {
            SchemaKind::Primitive(primitive) => {
                self.encode_primitive(value, *primitive, slot)?;
            }
            SchemaKind::Struct { fields, .. } => {
                let object = value
                    .as_object()
                    .ok_or(AlignedError::TypeMismatch("struct"))?;
                self.bytes[slot] = TAG_STRUCT;
                let child_slots = self.allocate_nodes(fields.len())?;
                self.write_children(slot, child_slots, fields.len())?;
                for (index, field) in fields.iter().enumerate() {
                    let child = object
                        .get(&VString::new(&field.name))
                        .ok_or(AlignedError::TypeMismatch("struct field"))?;
                    self.encode_node(
                        child,
                        &field.schema,
                        child_slots + index * NODE_SIZE,
                        depth + 1,
                    )?;
                }
            }
            SchemaKind::Tuple { elements } => {
                let array = value
                    .as_array()
                    .ok_or(AlignedError::TypeMismatch("tuple"))?;
                if array.len() != elements.len() {
                    return Err(AlignedError::TypeMismatch("tuple arity"));
                }
                self.bytes[slot] = TAG_TUPLE;
                let child_slots = self.allocate_nodes(elements.len())?;
                self.write_children(slot, child_slots, elements.len())?;
                for (index, element) in elements.iter().enumerate() {
                    self.encode_node(
                        array.get(index).expect("checked arity"),
                        element,
                        child_slots + index * NODE_SIZE,
                        depth + 1,
                    )?;
                }
            }
            SchemaKind::List { element } | SchemaKind::Set { element } => {
                let array = value.as_array().ok_or(AlignedError::TypeMismatch("list"))?;
                self.bytes[slot] = TAG_LIST;
                let child_slots = self.allocate_nodes(array.len())?;
                self.write_children(slot, child_slots, array.len())?;
                for index in 0..array.len() {
                    self.encode_node(
                        array.get(index).expect("in range"),
                        element,
                        child_slots + index * NODE_SIZE,
                        depth + 1,
                    )?;
                }
            }
            SchemaKind::Array {
                element,
                dimensions,
            } => {
                let expected = dimensions
                    .iter()
                    .try_fold(1usize, |count, dimension| {
                        count.checked_mul(*dimension as usize)
                    })
                    .ok_or(AlignedError::SizeOverflow)?;
                let array = value
                    .as_array()
                    .ok_or(AlignedError::TypeMismatch("array"))?;
                if array.len() != expected {
                    return Err(AlignedError::TypeMismatch("array length"));
                }
                self.bytes[slot] = TAG_LIST;
                let child_slots = self.allocate_nodes(array.len())?;
                self.write_children(slot, child_slots, array.len())?;
                for index in 0..array.len() {
                    self.encode_node(
                        array.get(index).expect("in range"),
                        element,
                        child_slots + index * NODE_SIZE,
                        depth + 1,
                    )?;
                }
            }
            SchemaKind::Option { element } => {
                if value.is_null() {
                    self.bytes[slot] = TAG_OPTION_NONE;
                } else {
                    self.bytes[slot] = TAG_OPTION_SOME;
                    let child_slot = self.allocate_nodes(1)?;
                    self.write_children(slot, child_slot, 1)?;
                    self.encode_node(value, element, child_slot, depth + 1)?;
                }
            }
            SchemaKind::Enum { variants, .. } => {
                let object = value
                    .as_object()
                    .ok_or(AlignedError::TypeMismatch("enum"))?;
                if object.len() != 1 {
                    return Err(AlignedError::TypeMismatch("enum variant"));
                }
                let (name, payload) = object.iter().next().expect("one variant");
                let variant = variants
                    .iter()
                    .find(|variant| variant.name == name.as_str())
                    .ok_or(AlignedError::TypeMismatch("known enum variant"))?;
                self.bytes[slot] = TAG_ENUM;
                self.bytes[slot + 4..slot + 8].copy_from_slice(&variant.index.to_le_bytes());
                self.encode_variant_payload(payload, &variant.payload, slot, depth)?;
            }
            SchemaKind::Map { .. }
            | SchemaKind::Tensor { .. }
            | SchemaKind::Channel { .. }
            | SchemaKind::Dynamic
            | SchemaKind::External { .. } => {
                return Err(AlignedError::Unsupported("schema kind in aligned profile"));
            }
        }
        Ok(())
    }

    fn encode_variant_payload(
        &mut self,
        value: &Value,
        payload: &VariantPayload,
        slot: usize,
        depth: usize,
    ) -> Result<(), AlignedError> {
        match payload {
            VariantPayload::Unit => {
                if !value.is_null() {
                    return Err(AlignedError::TypeMismatch("unit enum payload"));
                }
            }
            VariantPayload::Newtype(schema) => {
                let child_slot = self.allocate_nodes(1)?;
                self.write_children(slot, child_slot, 1)?;
                self.encode_node(value, schema, child_slot, depth + 1)?;
            }
            VariantPayload::Tuple(elements) => {
                let array = value
                    .as_array()
                    .ok_or(AlignedError::TypeMismatch("tuple enum payload"))?;
                if array.len() != elements.len() {
                    return Err(AlignedError::TypeMismatch("enum tuple arity"));
                }
                let child_slots = self.allocate_nodes(elements.len())?;
                self.write_children(slot, child_slots, elements.len())?;
                for (index, element) in elements.iter().enumerate() {
                    self.encode_node(
                        array.get(index).expect("checked arity"),
                        element,
                        child_slots + index * NODE_SIZE,
                        depth + 1,
                    )?;
                }
            }
            VariantPayload::Struct(fields) => {
                let object = value
                    .as_object()
                    .ok_or(AlignedError::TypeMismatch("struct enum payload"))?;
                let child_slots = self.allocate_nodes(fields.len())?;
                self.write_children(slot, child_slots, fields.len())?;
                for (index, field) in fields.iter().enumerate() {
                    let child = object
                        .get(&VString::new(&field.name))
                        .ok_or(AlignedError::TypeMismatch("enum struct field"))?;
                    self.encode_node(
                        child,
                        &field.schema,
                        child_slots + index * NODE_SIZE,
                        depth + 1,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn allocate_nodes(&mut self, count: usize) -> Result<usize, AlignedError> {
        let start = align_up(self.bytes.len(), NODE_ALIGN)?;
        self.bytes.resize(start, 0);
        let len = count
            .checked_mul(NODE_SIZE)
            .ok_or(AlignedError::SizeOverflow)?;
        self.bytes
            .resize(start.checked_add(len).ok_or(AlignedError::SizeOverflow)?, 0);
        Ok(start)
    }

    fn write_children(
        &mut self,
        slot: usize,
        offset: usize,
        count: usize,
    ) -> Result<(), AlignedError> {
        self.bytes[slot + 8..slot + 16].copy_from_slice(
            &u64::try_from(offset)
                .map_err(|_| AlignedError::SizeOverflow)?
                .to_le_bytes(),
        );
        self.bytes[slot + 16..slot + 24].copy_from_slice(
            &u64::try_from(count)
                .map_err(|_| AlignedError::SizeOverflow)?
                .to_le_bytes(),
        );
        Ok(())
    }

    fn write_payload(&mut self, slot: usize, payload: &[u8]) -> Result<(), AlignedError> {
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(payload);
        self.bytes[slot + 8..slot + 16].copy_from_slice(
            &u64::try_from(offset)
                .map_err(|_| AlignedError::SizeOverflow)?
                .to_le_bytes(),
        );
        self.bytes[slot + 16..slot + 24].copy_from_slice(
            &u64::try_from(payload.len())
                .map_err(|_| AlignedError::SizeOverflow)?
                .to_le_bytes(),
        );
        Ok(())
    }
}

/// Fully validated borrowed view of an aligned PHON document.
pub struct AlignedDocument<'a> {
    bytes: &'a [u8],
    root: SchemaId,
    registry: &'a AlignedRegistry,
}

impl<'a> AlignedDocument<'a> {
    pub fn parse(
        bytes: &'a [u8],
        expected_root: SchemaId,
        registry: &'a AlignedRegistry,
    ) -> Result<Self, AlignedError> {
        if bytes.len() < HEADER_SIZE + NODE_SIZE {
            return Err(AlignedError::Truncated {
                needed: HEADER_SIZE + NODE_SIZE,
                actual: bytes.len(),
            });
        }
        if bytes[..8] != MAGIC {
            return Err(AlignedError::BadMagic);
        }
        let version = read_u16(bytes, 8)?;
        if version != VERSION {
            return Err(AlignedError::UnsupportedVersion(version));
        }
        if bytes[10] != 1 {
            return Err(AlignedError::WrongByteOrder(bytes[10]));
        }
        if read_u32(bytes, 12)? as usize != HEADER_SIZE {
            return Err(AlignedError::BadHeader);
        }
        let root = SchemaId::from_raw(read_u64(bytes, 16)?);
        if root != expected_root {
            return Err(AlignedError::WrongSchema {
                expected: expected_root,
                actual: root,
            });
        }
        let root_offset = usize_from_u64(read_u64(bytes, 24)?)?;
        let file_len = usize_from_u64(read_u64(bytes, 32)?)?;
        if file_len != bytes.len() {
            return Err(AlignedError::Truncated {
                needed: file_len,
                actual: bytes.len(),
            });
        }
        if root_offset != HEADER_SIZE || !root_offset.is_multiple_of(NODE_ALIGN) {
            return Err(AlignedError::BadHeader);
        }
        let document = Self {
            bytes,
            root,
            registry,
        };
        document.validate_node(root_offset, &SchemaRef::concrete(root), 0)?;
        Ok(document)
    }

    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub fn root(&self) -> AlignedValue<'a, '_> {
        AlignedValue {
            document: self,
            offset: HEADER_SIZE,
            schema: SchemaRef::concrete(self.root),
        }
    }

    pub fn to_value(&self) -> Result<Value, AlignedError> {
        self.root().to_value(0)
    }

    fn validate_node(
        &self,
        offset: usize,
        schema: &SchemaRef,
        depth: usize,
    ) -> Result<(), AlignedError> {
        if depth > MAX_DEPTH {
            return Err(AlignedError::DepthExceeded);
        }
        self.node_bytes(offset)?;
        match resolve_aligned(self.registry, schema)? {
            compact::Resolved::Primitive(primitive) => self.validate_primitive(offset, primitive),
            compact::Resolved::Composite(kind) => self.validate_kind(offset, &kind, depth),
        }
    }

    fn validate_primitive(&self, offset: usize, primitive: Primitive) -> Result<(), AlignedError> {
        let expected = primitive_node_tag(primitive);
        self.expect_tag(offset, expected)?;
        if self.bytes[offset + 1] != primitive_tag(primitive) {
            return Err(AlignedError::WrongScalarKind {
                expected: primitive_tag(primitive),
                actual: self.bytes[offset + 1],
            });
        }
        if matches!(
            primitive,
            Primitive::String
                | Primitive::Bytes
                | Primitive::DateTime
                | Primitive::Uuid
                | Primitive::QName
        ) {
            let payload = self.reference(offset)?;
            if !matches!(primitive, Primitive::Bytes) {
                std::str::from_utf8(payload).map_err(|_| AlignedError::InvalidUtf8)?;
            }
        }
        Ok(())
    }

    fn validate_kind(
        &self,
        offset: usize,
        kind: &SchemaKind,
        depth: usize,
    ) -> Result<(), AlignedError> {
        match kind {
            SchemaKind::Primitive(primitive) => self.validate_primitive(offset, *primitive),
            SchemaKind::Struct { fields, .. } => {
                self.expect_tag(offset, TAG_STRUCT)?;
                let children = self.children(offset, fields.len())?;
                for (index, field) in fields.iter().enumerate() {
                    self.validate_node(children + index * NODE_SIZE, &field.schema, depth + 1)?;
                }
                Ok(())
            }
            SchemaKind::Tuple { elements } => {
                self.expect_tag(offset, TAG_TUPLE)?;
                let children = self.children(offset, elements.len())?;
                for (index, element) in elements.iter().enumerate() {
                    self.validate_node(children + index * NODE_SIZE, element, depth + 1)?;
                }
                Ok(())
            }
            SchemaKind::List { element } | SchemaKind::Set { element } => {
                self.expect_tag(offset, TAG_LIST)?;
                let count = usize_from_u64(read_u64(self.bytes, offset + 16)?)?;
                let children = self.children(offset, count)?;
                for index in 0..count {
                    self.validate_node(children + index * NODE_SIZE, element, depth + 1)?;
                }
                Ok(())
            }
            SchemaKind::Array {
                element,
                dimensions,
            } => {
                self.expect_tag(offset, TAG_LIST)?;
                let expected = dimensions
                    .iter()
                    .try_fold(1usize, |count, dimension| {
                        count.checked_mul(*dimension as usize)
                    })
                    .ok_or(AlignedError::SizeOverflow)?;
                let children = self.children(offset, expected)?;
                for index in 0..expected {
                    self.validate_node(children + index * NODE_SIZE, element, depth + 1)?;
                }
                Ok(())
            }
            SchemaKind::Option { element } => match self.bytes[offset] {
                TAG_OPTION_NONE => Ok(()),
                TAG_OPTION_SOME => {
                    let child = self.children(offset, 1)?;
                    self.validate_node(child, element, depth + 1)
                }
                actual => Err(AlignedError::WrongNodeKind {
                    expected: TAG_OPTION_NONE,
                    actual,
                }),
            },
            SchemaKind::Enum { variants, .. } => {
                self.expect_tag(offset, TAG_ENUM)?;
                let variant_index = read_u32(self.bytes, offset + 4)?;
                let variant = variants
                    .iter()
                    .find(|variant| variant.index == variant_index)
                    .ok_or(AlignedError::UnknownVariant(variant_index))?;
                self.validate_variant_payload(offset, &variant.payload, depth)
            }
            SchemaKind::Map { .. }
            | SchemaKind::Tensor { .. }
            | SchemaKind::Channel { .. }
            | SchemaKind::Dynamic
            | SchemaKind::External { .. } => {
                Err(AlignedError::Unsupported("schema kind in aligned profile"))
            }
        }
    }

    fn validate_variant_payload(
        &self,
        offset: usize,
        payload: &VariantPayload,
        depth: usize,
    ) -> Result<(), AlignedError> {
        match payload {
            VariantPayload::Unit => Ok(()),
            VariantPayload::Newtype(schema) => {
                let child = self.children(offset, 1)?;
                self.validate_node(child, schema, depth + 1)
            }
            VariantPayload::Tuple(elements) => {
                let children = self.children(offset, elements.len())?;
                for (index, element) in elements.iter().enumerate() {
                    self.validate_node(children + index * NODE_SIZE, element, depth + 1)?;
                }
                Ok(())
            }
            VariantPayload::Struct(fields) => {
                let children = self.children(offset, fields.len())?;
                for (index, field) in fields.iter().enumerate() {
                    self.validate_node(children + index * NODE_SIZE, &field.schema, depth + 1)?;
                }
                Ok(())
            }
        }
    }

    fn node_bytes(&self, offset: usize) -> Result<&'a [u8], AlignedError> {
        let end = offset
            .checked_add(NODE_SIZE)
            .ok_or(AlignedError::SizeOverflow)?;
        self.bytes
            .get(offset..end)
            .ok_or(AlignedError::ReferenceOutOfBounds {
                offset: offset as u64,
                len: NODE_SIZE as u64,
                file_len: self.bytes.len(),
            })
    }

    fn expect_tag(&self, offset: usize, expected: u8) -> Result<(), AlignedError> {
        let actual = self.node_bytes(offset)?[0];
        if actual == expected {
            Ok(())
        } else {
            Err(AlignedError::WrongNodeKind { expected, actual })
        }
    }

    fn children(&self, offset: usize, expected_count: usize) -> Result<usize, AlignedError> {
        let child_offset = usize_from_u64(read_u64(self.bytes, offset + 8)?)?;
        let count = usize_from_u64(read_u64(self.bytes, offset + 16)?)?;
        if count != expected_count {
            return Err(AlignedError::WrongChildCount {
                expected: expected_count,
                actual: count,
            });
        }
        if !child_offset.is_multiple_of(NODE_ALIGN) {
            return Err(AlignedError::MisalignedReference {
                offset: child_offset as u64,
                alignment: NODE_ALIGN,
            });
        }
        let len = count
            .checked_mul(NODE_SIZE)
            .ok_or(AlignedError::SizeOverflow)?;
        let end = child_offset
            .checked_add(len)
            .ok_or(AlignedError::SizeOverflow)?;
        if child_offset < HEADER_SIZE + NODE_SIZE || end > self.bytes.len() {
            return Err(AlignedError::ReferenceOutOfBounds {
                offset: child_offset as u64,
                len: len as u64,
                file_len: self.bytes.len(),
            });
        }
        Ok(child_offset)
    }

    fn reference(&self, offset: usize) -> Result<&'a [u8], AlignedError> {
        let target = usize_from_u64(read_u64(self.bytes, offset + 8)?)?;
        let len = usize_from_u64(read_u64(self.bytes, offset + 16)?)?;
        let end = target.checked_add(len).ok_or(AlignedError::SizeOverflow)?;
        self.bytes
            .get(target..end)
            .ok_or(AlignedError::ReferenceOutOfBounds {
                offset: target as u64,
                len: len as u64,
                file_len: self.bytes.len(),
            })
    }
}

/// One borrowed value inside an admitted aligned document.
pub struct AlignedValue<'a, 'document> {
    document: &'document AlignedDocument<'a>,
    offset: usize,
    schema: SchemaRef,
}

impl<'a, 'document> AlignedValue<'a, 'document> {
    pub fn index(&self, index: usize) -> Result<Self, AlignedError> {
        match resolve_aligned(self.document.registry, &self.schema)? {
            compact::Resolved::Composite(
                SchemaKind::List { element }
                | SchemaKind::Set { element }
                | SchemaKind::Array { element, .. },
            ) => {
                let count = usize_from_u64(read_u64(self.document.bytes, self.offset + 16)?)?;
                if index >= count {
                    return Err(AlignedError::IndexOutOfBounds { index, count });
                }
                let children = self.document.children(self.offset, count)?;
                Ok(Self {
                    document: self.document,
                    offset: children + index * NODE_SIZE,
                    schema: element.clone(),
                })
            }
            compact::Resolved::Composite(SchemaKind::Tuple { elements }) => {
                let schema = elements
                    .get(index)
                    .ok_or(AlignedError::IndexOutOfBounds {
                        index,
                        count: elements.len(),
                    })?
                    .clone();
                let children = self.document.children(self.offset, elements.len())?;
                Ok(Self {
                    document: self.document,
                    offset: children + index * NODE_SIZE,
                    schema,
                })
            }
            _ => Err(AlignedError::TypeMismatch("indexable value")),
        }
    }

    /// Number of elements in a list, set, array, or tuple.
    pub fn len(&self) -> Result<usize, AlignedError> {
        match resolve_aligned(self.document.registry, &self.schema)? {
            compact::Resolved::Composite(
                SchemaKind::List { .. } | SchemaKind::Set { .. } | SchemaKind::Array { .. },
            ) => usize_from_u64(read_u64(self.document.bytes, self.offset + 16)?),
            compact::Resolved::Composite(SchemaKind::Tuple { ref elements }) => Ok(elements.len()),
            _ => Err(AlignedError::TypeMismatch("sequence")),
        }
    }

    /// Whether this sequence contains no elements.
    pub fn is_empty(&self) -> Result<bool, AlignedError> {
        Ok(self.len()? == 0)
    }

    pub fn field(&self, name: &str) -> Result<Self, AlignedError> {
        match resolve_aligned(self.document.registry, &self.schema)? {
            compact::Resolved::Composite(SchemaKind::Struct { fields, .. }) => {
                let (index, field) = fields
                    .iter()
                    .enumerate()
                    .find(|(_, field)| field.name == name)
                    .ok_or_else(|| AlignedError::UnknownField(name.to_owned()))?;
                let children = self.document.children(self.offset, fields.len())?;
                Ok(Self {
                    document: self.document,
                    offset: children + index * NODE_SIZE,
                    schema: field.schema.clone(),
                })
            }
            _ => Err(AlignedError::TypeMismatch("struct")),
        }
    }

    pub fn as_u32(&self) -> Result<u32, AlignedError> {
        self.expect_primitive(Primitive::U32)?;
        Ok(read_u128(self.document.bytes, self.offset + 8)? as u32)
    }

    pub fn as_u64(&self) -> Result<u64, AlignedError> {
        self.expect_primitive(Primitive::U64)?;
        Ok(read_u128(self.document.bytes, self.offset + 8)? as u64)
    }

    pub fn as_str(&self) -> Result<&'a str, AlignedError> {
        match resolve_aligned(self.document.registry, &self.schema)? {
            compact::Resolved::Primitive(
                Primitive::String | Primitive::DateTime | Primitive::Uuid | Primitive::QName,
            ) => std::str::from_utf8(self.document.reference(self.offset)?)
                .map_err(|_| AlignedError::InvalidUtf8),
            _ => Err(AlignedError::TypeMismatch("string")),
        }
    }

    fn expect_primitive(&self, expected: Primitive) -> Result<(), AlignedError> {
        match resolve_aligned(self.document.registry, &self.schema)? {
            compact::Resolved::Primitive(actual) if actual == expected => Ok(()),
            _ => Err(AlignedError::TypeMismatch(expected.tag())),
        }
    }

    fn to_value(&self, depth: usize) -> Result<Value, AlignedError> {
        if depth > MAX_DEPTH {
            return Err(AlignedError::DepthExceeded);
        }
        match resolve_aligned(self.document.registry, &self.schema)? {
            compact::Resolved::Primitive(primitive) => self.primitive_to_value(primitive),
            compact::Resolved::Composite(kind) => self.kind_to_value(&kind, depth),
        }
    }

    fn primitive_to_value(&self, primitive: Primitive) -> Result<Value, AlignedError> {
        Ok(match primitive {
            Primitive::Unit => Value::NULL,
            Primitive::Bool => Value::from(self.document.bytes[self.offset + 8] != 0),
            Primitive::U8 => Value::from(read_u128(self.document.bytes, self.offset + 8)? as u8),
            Primitive::U16 => Value::from(read_u128(self.document.bytes, self.offset + 8)? as u16),
            Primitive::U32 => Value::from(read_u128(self.document.bytes, self.offset + 8)? as u32),
            Primitive::U64 => Value::from(read_u128(self.document.bytes, self.offset + 8)? as u64),
            Primitive::U128 => Value::from(read_u128(self.document.bytes, self.offset + 8)?),
            Primitive::I8 => Value::from(read_i128(self.document.bytes, self.offset + 8)? as i8),
            Primitive::I16 => Value::from(read_i128(self.document.bytes, self.offset + 8)? as i16),
            Primitive::I32 => Value::from(read_i128(self.document.bytes, self.offset + 8)? as i32),
            Primitive::I64 => Value::from(read_i128(self.document.bytes, self.offset + 8)? as i64),
            Primitive::I128 => Value::from(read_i128(self.document.bytes, self.offset + 8)?),
            Primitive::F32 => {
                Value::from(f64::from_bits(read_u64(self.document.bytes, self.offset + 8)?) as f32)
            }
            Primitive::F64 => Value::from(f64::from_bits(read_u64(
                self.document.bytes,
                self.offset + 8,
            )?)),
            Primitive::Char => Value::from(
                char::from_u32(read_u32(self.document.bytes, self.offset + 8)?)
                    .ok_or(AlignedError::InvalidChar)?,
            ),
            Primitive::String | Primitive::DateTime | Primitive::Uuid | Primitive::QName => {
                Value::from(self.as_str()?)
            }
            Primitive::Bytes => Value::from(VBytes::new(self.document.reference(self.offset)?)),
            Primitive::Never => return Err(AlignedError::TypeMismatch("never")),
        })
    }

    fn kind_to_value(&self, kind: &SchemaKind, depth: usize) -> Result<Value, AlignedError> {
        match kind {
            SchemaKind::Primitive(primitive) => self.primitive_to_value(*primitive),
            SchemaKind::Struct { fields, .. } => {
                let children = self.document.children(self.offset, fields.len())?;
                let mut object = VObject::new();
                for (index, field) in fields.iter().enumerate() {
                    object.insert(
                        VString::new(&field.name),
                        AlignedValue {
                            document: self.document,
                            offset: children + index * NODE_SIZE,
                            schema: field.schema.clone(),
                        }
                        .to_value(depth + 1)?,
                    );
                }
                Ok(object.into())
            }
            SchemaKind::Tuple { elements } => self.sequence_to_value(elements, depth),
            SchemaKind::List { element } | SchemaKind::Set { element } => {
                let count = usize_from_u64(read_u64(self.document.bytes, self.offset + 16)?)?;
                let schemas = vec![element.clone(); count];
                self.sequence_to_value(&schemas, depth)
            }
            SchemaKind::Array {
                element,
                dimensions,
            } => {
                let count = dimensions
                    .iter()
                    .try_fold(1usize, |count, dimension| {
                        count.checked_mul(*dimension as usize)
                    })
                    .ok_or(AlignedError::SizeOverflow)?;
                let schemas = vec![element.clone(); count];
                self.sequence_to_value(&schemas, depth)
            }
            SchemaKind::Option { element } => {
                if self.document.bytes[self.offset] == TAG_OPTION_NONE {
                    Ok(Value::NULL)
                } else {
                    let child = self.document.children(self.offset, 1)?;
                    AlignedValue {
                        document: self.document,
                        offset: child,
                        schema: element.clone(),
                    }
                    .to_value(depth + 1)
                }
            }
            SchemaKind::Enum { variants, .. } => {
                let variant_index = read_u32(self.document.bytes, self.offset + 4)?;
                let variant = variants
                    .iter()
                    .find(|variant| variant.index == variant_index)
                    .ok_or(AlignedError::UnknownVariant(variant_index))?;
                let payload = self.variant_payload_to_value(&variant.payload, depth)?;
                let mut object = VObject::new();
                object.insert(VString::new(&variant.name), payload);
                Ok(object.into())
            }
            _ => Err(AlignedError::Unsupported("schema kind in aligned profile")),
        }
    }

    fn sequence_to_value(
        &self,
        schemas: &[SchemaRef],
        depth: usize,
    ) -> Result<Value, AlignedError> {
        let children = self.document.children(self.offset, schemas.len())?;
        let mut array = VArray::new();
        for (index, schema) in schemas.iter().enumerate() {
            array.push(
                AlignedValue {
                    document: self.document,
                    offset: children + index * NODE_SIZE,
                    schema: schema.clone(),
                }
                .to_value(depth + 1)?,
            );
        }
        Ok(array.into())
    }

    fn variant_payload_to_value(
        &self,
        payload: &VariantPayload,
        depth: usize,
    ) -> Result<Value, AlignedError> {
        match payload {
            VariantPayload::Unit => Ok(Value::NULL),
            VariantPayload::Newtype(schema) => {
                let child = self.document.children(self.offset, 1)?;
                AlignedValue {
                    document: self.document,
                    offset: child,
                    schema: schema.clone(),
                }
                .to_value(depth + 1)
            }
            VariantPayload::Tuple(elements) => self.sequence_to_value(elements, depth),
            VariantPayload::Struct(fields) => {
                let children = self.document.children(self.offset, fields.len())?;
                let mut object = VObject::new();
                for (index, field) in fields.iter().enumerate() {
                    object.insert(
                        VString::new(&field.name),
                        AlignedValue {
                            document: self.document,
                            offset: children + index * NODE_SIZE,
                            schema: field.schema.clone(),
                        }
                        .to_value(depth + 1)?,
                    );
                }
                Ok(object.into())
            }
        }
    }
}

fn primitive_node_tag(primitive: Primitive) -> u8 {
    match primitive {
        Primitive::Unit => TAG_UNIT,
        Primitive::Bool => TAG_BOOL,
        Primitive::U8 | Primitive::U16 | Primitive::U32 | Primitive::U64 | Primitive::U128 => {
            TAG_UNSIGNED
        }
        Primitive::I8 | Primitive::I16 | Primitive::I32 | Primitive::I64 | Primitive::I128 => {
            TAG_SIGNED
        }
        Primitive::F32 | Primitive::F64 => TAG_FLOAT,
        Primitive::Char => TAG_CHAR,
        Primitive::String | Primitive::DateTime | Primitive::Uuid | Primitive::QName => TAG_STRING,
        Primitive::Bytes => TAG_BYTES,
        Primitive::Never => TAG_UNIT,
    }
}

fn primitive_tag(primitive: Primitive) -> u8 {
    Primitive::ALL
        .iter()
        .position(|candidate| *candidate == primitive)
        .expect("primitive listed") as u8
}

fn align_up(value: usize, alignment: usize) -> Result<usize, AlignedError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(AlignedError::SizeOverflow)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AlignedError> {
    Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AlignedError> {
    Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AlignedError> {
    Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}
fn read_u128(bytes: &[u8], offset: usize) -> Result<u128, AlignedError> {
    Ok(u128::from_le_bytes(read_array(bytes, offset)?))
}
fn read_i128(bytes: &[u8], offset: usize) -> Result<i128, AlignedError> {
    Ok(i128::from_le_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], AlignedError> {
    let end = offset.checked_add(N).ok_or(AlignedError::SizeOverflow)?;
    bytes
        .get(offset..end)
        .ok_or(AlignedError::ReferenceOutOfBounds {
            offset: offset as u64,
            len: N as u64,
            file_len: bytes.len(),
        })?
        .try_into()
        .map_err(|_| AlignedError::ReferenceOutOfBounds {
            offset: offset as u64,
            len: N as u64,
            file_len: bytes.len(),
        })
}

fn usize_from_u64(value: u64) -> Result<usize, AlignedError> {
    usize::try_from(value).map_err(|_| AlignedError::SizeOverflow)
}

/// Why aligned PHON encoding or admission failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlignedError {
    UnknownSchema(SchemaId),
    BundleSchemaIdMismatch {
        stated: SchemaId,
        recomputed: SchemaId,
    },
    Compact(compact::CompactError),
    Unsupported(&'static str),
    TypeMismatch(&'static str),
    SizeOverflow,
    MisalignedReference {
        offset: u64,
        alignment: usize,
    },
    DepthExceeded,
    Truncated {
        needed: usize,
        actual: usize,
    },
    BadMagic,
    UnsupportedVersion(u16),
    WrongByteOrder(u8),
    BadHeader,
    WrongSchema {
        expected: SchemaId,
        actual: SchemaId,
    },
    ReferenceOutOfBounds {
        offset: u64,
        len: u64,
        file_len: usize,
    },
    WrongNodeKind {
        expected: u8,
        actual: u8,
    },
    WrongScalarKind {
        expected: u8,
        actual: u8,
    },
    WrongChildCount {
        expected: usize,
        actual: usize,
    },
    UnknownVariant(u32),
    UnknownField(String),
    IndexOutOfBounds {
        index: usize,
        count: usize,
    },
    InvalidUtf8,
    InvalidChar,
}

impl AlignedError {
    fn from_compact(error: compact::CompactError) -> Self {
        match error {
            compact::CompactError::BundleSchemaIdMismatch { stated, recomputed } => {
                Self::BundleSchemaIdMismatch { stated, recomputed }
            }
            compact::CompactError::UnknownSchema(schema) => Self::UnknownSchema(schema),
            error => Self::Compact(error),
        }
    }
}

impl fmt::Display for AlignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aligned PHON error: {self:?}")
    }
}
impl std::error::Error for AlignedError {}
