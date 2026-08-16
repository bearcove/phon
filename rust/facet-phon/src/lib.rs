//! Acyclic typed Facet binding for PHON schemas and compact values.

use core::fmt;
use core::marker::PhantomData;

use facet::{Facet, taxon_bridge};
use facet_value::{from_value, to_value};
use phon_schema::{Schema, SchemaId, resolve_ids};
use phon_storage::compact::{self, Registry};

#[derive(Debug)]
pub enum Error {
    EncodeValue(String),
    DecodeValue(String),
    Compact(compact::CompactError),
    MissingRoot,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodeValue(error) => write!(f, "cannot reflect Facet value: {error}"),
            Self::DecodeValue(error) => write!(f, "cannot construct Facet value: {error}"),
            Self::Compact(error) => write!(f, "{error}"),
            Self::MissingRoot => write!(f, "Facet schema projection produced no root"),
        }
    }
}

impl std::error::Error for Error {}

impl From<compact::CompactError> for Error {
    fn from(error: compact::CompactError) -> Self {
        Self::Compact(error)
    }
}

pub struct Codec<T> {
    root: SchemaId,
    schemas: Vec<Schema>,
    registry: Registry,
    marker: PhantomData<fn() -> T>,
}

impl<T> Codec<T>
where
    T: Facet<'static>,
{
    pub fn new() -> Result<Self, Error> {
        let schemas = resolve_ids(taxon_bridge::schemas_of(T::SHAPE));
        let root = schemas
            .first()
            .map(|schema| schema.id)
            .ok_or(Error::MissingRoot)?;
        let registry = Registry::try_new(schemas.clone())?;
        Ok(Self {
            root,
            schemas,
            registry,
            marker: PhantomData,
        })
    }

    pub const fn root(&self) -> SchemaId {
        self.root
    }

    pub fn schemas(&self) -> &[Schema] {
        &self.schemas
    }

    pub fn encode(&self, value: &T) -> Result<Vec<u8>, Error> {
        let value = to_value(value).map_err(|error| Error::EncodeValue(error.to_string()))?;
        compact::to_bytes(&value, self.root, &self.registry).map_err(Into::into)
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<T, Error> {
        let value = compact::from_bytes(bytes, self.root, &self.registry)?;
        from_value(value).map_err(|error| Error::DecodeValue(error.to_string()))
    }
}
