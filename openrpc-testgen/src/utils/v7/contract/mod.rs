pub mod declare_and_deploy;
pub mod factory;
pub mod helpers;
pub mod unsigned_felt;
use serde::{de::Visitor, ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};
use serde_json_pythonic::to_string_pythonic;
use serde_with::serde_as;

use super::{
    accounts::account::{
        cairo_short_string_to_felt, normalize_address, starknet_keccak, CairoShortStringToFeltError,
    },
    contract::unsigned_felt::UfeHex,
};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};
use starknet_types_rpc::v0_7_1::{ContractClass, DeprecatedContractClass};

use std::boxed;

/// Cairo string for "CONTRACT_CLASS_V0.1.0"
const PREFIX_CONTRACT_CLASS_V0_1_0: Felt = Felt::from_raw([
    37302452645455172,
    18446734822722598327,
    15539482671244488427,
    5800711240972404213,
]);

/// Cairo string for `COMPILED_CLASS_V1`
const PREFIX_COMPILED_CLASS_V1: Felt = Felt::from_raw([
    324306817650036332,
    18446744073709549462,
    1609463842841646376,
    2291010424822318237,
]);

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
#[allow(clippy::enum_variant_names)]
pub enum ContractArtifact {
    SierraClass(SierraClass),
    CompiledClass(CompiledClass),
    LegacyClass(DeprecatedContractClass<Felt>),
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct SierraClass {
    #[serde_as(as = "Vec<UfeHex>")]
    pub sierra_program: Vec<Felt>,
    pub sierra_program_debug_info: SierraClassDebugInfo,
    pub contract_class_version: String,
    pub entry_points_by_type: EntryPointsByType<Felt>,
    pub abi: Vec<AbiEntry>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct CompiledClass {
    pub prime: String,
    pub compiler_version: String,

    pub bytecode: Vec<Felt>,
    /// Represents the structure of the bytecode segments, using a nested list of segment lengths.
    /// For example, [2, [3, 4]] represents a bytecode with 2 segments, the first is a leaf of
    /// length 2 and the second is a node with 2 children of lengths 3 and 4.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bytecode_segment_lengths: Vec<IntOrList>,
    pub hints: Vec<Hint>,
    pub pythonic_hints: Option<Vec<PythonicHint>>,
    pub entry_points_by_type: CompiledClassEntrypointList,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct SierraClassDebugInfo {
    pub type_names: Vec<(u64, String)>,
    pub libfunc_names: Vec<(u64, String)>,
    pub user_func_names: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct CompiledClassEntrypointList {
    pub external: Vec<CompiledClassEntrypoint>,
    pub l1_handler: Vec<CompiledClassEntrypoint>,
    pub constructor: Vec<CompiledClassEntrypoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub enum AbiEntry {
    Function(AbiFunction),
    Event(AbiEvent),
    Struct(AbiStruct),
    Enum(AbiEnum),
    Constructor(AbiConstructor),
    Impl(AbiImpl),
    Interface(AbiInterface),
    L1Handler(AbiFunction),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hint {
    pub id: u64,
    // For convenience we just treat it as an opaque JSON value here, unless a use case justifies
    // implementing the structure. (We no longer need the hints for the class hash anyways.)
    pub code: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct PythonicHint {
    pub id: u64,
    pub code: Vec<String>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct CompiledClassEntrypoint {
    #[serde_as(as = "UfeHex")]
    pub selector: Felt,
    pub offset: u64,
    pub builtins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiFunction {
    pub name: String,
    pub inputs: Vec<AbiNamedMember>,
    pub outputs: Vec<AbiOutput>,
    pub state_mutability: StateMutability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
#[serde(untagged)]
pub enum AbiEvent {
    /// Cairo 2.x ABI event entry
    Typed(TypedAbiEvent),
    /// Cairo 1.x ABI event entry
    Untyped(UntypedAbiEvent),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub enum TypedAbiEvent {
    Struct(AbiEventStruct),
    Enum(AbiEventEnum),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct UntypedAbiEvent {
    pub name: String,
    pub inputs: Vec<AbiNamedMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiEventStruct {
    pub name: String,
    pub members: Vec<EventField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiEventEnum {
    pub name: String,
    pub variants: Vec<EventField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiStruct {
    pub name: String,
    pub members: Vec<AbiNamedMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiConstructor {
    pub name: String,
    pub inputs: Vec<AbiNamedMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiImpl {
    pub name: String,
    pub interface_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiInterface {
    pub name: String,
    pub items: Vec<AbiEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiEnum {
    pub name: String,
    pub variants: Vec<AbiNamedMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiNamedMember {
    pub name: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct AbiOutput {
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct EventField {
    pub name: String,
    pub r#type: String,
    pub kind: EventFieldKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateMutability {
    External,
    View,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventFieldKind {
    Key,
    Data,
    Nested,
    Flat,
}

#[derive(Debug, Clone)]
pub enum IntOrList {
    Int(u64),
    List(Vec<IntOrList>),
}

struct IntOrListVisitor;

/// Internal structure used for post-Sierra-1.5.0 CASM hash calculation.
enum BytecodeSegmentStructure {
    BytecodeLeaf(BytecodeLeaf),
    BytecodeSegmentedNode(BytecodeSegmentedNode),
}

/// Internal structure used for post-Sierra-1.5.0 CASM hash calculation.
///
/// Represents a leaf in the bytecode segment tree.
struct BytecodeLeaf {
    // NOTE: change this to a slice?
    data: Vec<Felt>,
}

/// Internal structure used for post-Sierra-1.5.0 CASM hash calculation.
///
/// Represents an internal node in the bytecode segment tree. Each child can be loaded into memory
/// or skipped.
struct BytecodeSegmentedNode {
    segments: Vec<BytecodeSegment>,
}

/// Internal structure used for post-Sierra-1.5.0 CASM hash calculation.
///
/// Represents a child of [BytecodeSegmentedNode].
struct BytecodeSegment {
    segment_length: u64,
    #[allow(unused)]
    is_used: bool,
    inner_structure: boxed::Box<BytecodeSegmentStructure>,
}

mod errors {
    use core::fmt::{Display, Formatter, Result};

    #[derive(Debug)]
    pub enum ComputeClassHashError {
        InvalidBuiltinName,
        BytecodeSegmentLengthMismatch(BytecodeSegmentLengthMismatchError),
        InvalidBytecodeSegment(InvalidBytecodeSegmentError),
        PcOutOfRange(PcOutOfRangeError),
        Json(JsonError),
    }

    #[derive(Debug)]
    pub struct JsonError {
        pub(crate) message: String,
    }

    #[derive(Debug)]
    pub struct BytecodeSegmentLengthMismatchError {
        pub segment_length: usize,
        pub bytecode_length: usize,
    }

    #[derive(Debug)]
    pub struct InvalidBytecodeSegmentError {
        pub visited_pc: u64,
        pub segment_start: u64,
    }

    #[derive(Debug)]
    pub struct PcOutOfRangeError {
        pub pc: u64,
    }

    impl std::error::Error for ComputeClassHashError {}

    impl Display for ComputeClassHashError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            match self {
                Self::InvalidBuiltinName => write!(f, "invalid builtin name"),
                Self::BytecodeSegmentLengthMismatch(inner) => write!(f, "{}", inner),
                Self::InvalidBytecodeSegment(inner) => write!(f, "{}", inner),
                Self::PcOutOfRange(inner) => write!(f, "{}", inner),
                Self::Json(inner) => write!(f, "json serialization error: {}", inner),
            }
        }
    }

    impl std::error::Error for JsonError {}

    impl Display for JsonError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            write!(f, "{}", self.message)
        }
    }

    impl std::error::Error for BytecodeSegmentLengthMismatchError {}

    impl Display for BytecodeSegmentLengthMismatchError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            write!(
                f,
                "invalid bytecode segment structure length: {}, bytecode length: {}.",
                self.segment_length, self.bytecode_length,
            )
        }
    }

    impl std::error::Error for InvalidBytecodeSegmentError {}

    impl Display for InvalidBytecodeSegmentError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            write!(
                f,
                "invalid segment structure: PC {} was visited, \
                but the beginning of the segment ({}) was not",
                self.visited_pc, self.segment_start
            )
        }
    }

    impl std::error::Error for PcOutOfRangeError {}

    impl Display for PcOutOfRangeError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            write!(f, "PC {} is out of range", self.pc)
        }
    }
}
pub use errors::{
    BytecodeSegmentLengthMismatchError, ComputeClassHashError, InvalidBytecodeSegmentError,
    JsonError, PcOutOfRangeError,
};

use starknet_types_rpc::v0_7_1::{EntryPointsByType, SierraEntryPoint};

pub trait HashAndFlatten {
    fn class_hash(&self) -> Result<Felt, ComputeClassHashError>;

    fn flatten(self) -> Result<ContractClass<Felt>, JsonError>;
}

impl HashAndFlatten for SierraClass {
    fn class_hash(&self) -> Result<Felt, ComputeClassHashError> {
        let abi_str = to_string_pythonic(&self.abi).map_err(|err| {
            ComputeClassHashError::Json(JsonError {
                message: format!("{}", err),
            })
        })?;

        let data = vec![
            PREFIX_CONTRACT_CLASS_V0_1_0,
            hash_sierra_entrypoints(&self.entry_points_by_type.external),
            hash_sierra_entrypoints(&self.entry_points_by_type.l1_handler),
            hash_sierra_entrypoints(&self.entry_points_by_type.constructor),
            starknet_keccak(abi_str.as_bytes()),
            Poseidon::hash_array(&self.sierra_program),
        ];

        Ok(normalize_address(Poseidon::hash_array(&data)))
    }

    fn flatten(self) -> Result<ContractClass<Felt>, JsonError> {
        let abi = to_string_pythonic(&self.abi).map_err(|err| JsonError {
            message: format!("{}", err),
        })?;

        Ok(ContractClass {
            sierra_program: self.sierra_program,
            entry_points_by_type: self.entry_points_by_type,
            abi: Some(abi),
            contract_class_version: self.contract_class_version,
        })
    }
}

impl CompiledClass {
    pub fn class_hash(&self) -> Result<Felt, ComputeClassHashError> {
        let mut data = vec![
            PREFIX_COMPILED_CLASS_V1,
            Self::hash_entrypoints(&self.entry_points_by_type.external)
                .map_err(|_| ComputeClassHashError::InvalidBuiltinName)?,
            Self::hash_entrypoints(&self.entry_points_by_type.l1_handler)
                .map_err(|_| ComputeClassHashError::InvalidBuiltinName)?,
            Self::hash_entrypoints(&self.entry_points_by_type.constructor)
                .map_err(|_| ComputeClassHashError::InvalidBuiltinName)?,
        ];

        // Bytecode hash calculation
        let bytecode_hash = if self.bytecode_segment_lengths.is_empty() {
            Poseidon::hash_array(&self.bytecode)
        } else {
            let mut rev_visited_pcs: Vec<u64> = (0..(self.bytecode.len() as u64)).rev().collect();

            let (res, total_len) = Self::create_bytecode_segment_structure_inner(
                &self.bytecode,
                &IntOrList::List(self.bytecode_segment_lengths.clone()),
                &mut rev_visited_pcs,
                &mut 0,
            )?;

            if total_len != self.bytecode.len() as u64 {
                return Err(ComputeClassHashError::BytecodeSegmentLengthMismatch(
                    BytecodeSegmentLengthMismatchError {
                        segment_length: total_len as usize,
                        bytecode_length: self.bytecode.len(),
                    },
                ));
            }
            if !rev_visited_pcs.is_empty() {
                return Err(ComputeClassHashError::PcOutOfRange(PcOutOfRangeError {
                    pc: rev_visited_pcs[rev_visited_pcs.len() - 1],
                }));
            }

            res.hash()
        };
        data.push(bytecode_hash);

        Ok(Poseidon::hash_array(&data))
    }

    fn hash_entrypoints(
        entrypoints: &[CompiledClassEntrypoint],
    ) -> Result<Felt, CairoShortStringToFeltError> {
        let mut data = Vec::new();

        for entry in entrypoints {
            data.push(entry.selector);
            data.push(entry.offset.into());

            let mut builtin_data = Vec::new();
            for builtin in &entry.builtins {
                builtin_data.push(cairo_short_string_to_felt(builtin)?);
            }

            data.push(Poseidon::hash_array(&builtin_data));
        }

        Ok(Poseidon::hash_array(&data))
    }

    // Direct translation of `_create_bytecode_segment_structure_inner` from `cairo-lang` v0.13.1.
    //
    // `visited_pcs` should be given in reverse order, and is consumed by the function. Returns the
    // BytecodeSegmentStructure and the total length of the processed segment.
    fn create_bytecode_segment_structure_inner(
        bytecode: &[Felt],
        bytecode_segment_lengths: &IntOrList,
        visited_pcs: &mut Vec<u64>,
        bytecode_offset: &mut u64,
    ) -> Result<(BytecodeSegmentStructure, u64), ComputeClassHashError> {
        match bytecode_segment_lengths {
            IntOrList::Int(bytecode_segment_lengths) => {
                let segment_end = *bytecode_offset + bytecode_segment_lengths;

                // Remove all the visited PCs that are in the segment.
                while !visited_pcs.is_empty()
                    && *bytecode_offset <= visited_pcs[visited_pcs.len() - 1]
                    && visited_pcs[visited_pcs.len() - 1] < segment_end
                {
                    visited_pcs.pop();
                }

                Ok((
                    BytecodeSegmentStructure::BytecodeLeaf(BytecodeLeaf {
                        data: bytecode[(*bytecode_offset as usize)..(segment_end as usize)]
                            .to_vec(),
                    }),
                    *bytecode_segment_lengths,
                ))
            }
            IntOrList::List(bytecode_segment_lengths) => {
                let mut res = Vec::new();
                let mut total_len = 0;

                for item in bytecode_segment_lengths {
                    let visited_pc_before = if !visited_pcs.is_empty() {
                        Some(visited_pcs[visited_pcs.len() - 1])
                    } else {
                        None
                    };

                    let (current_structure, item_len) =
                        Self::create_bytecode_segment_structure_inner(
                            bytecode,
                            item,
                            visited_pcs,
                            bytecode_offset,
                        )?;

                    let visited_pc_after = if !visited_pcs.is_empty() {
                        Some(visited_pcs[visited_pcs.len() - 1])
                    } else {
                        None
                    };
                    let is_used = visited_pc_after != visited_pc_before;

                    if let Some(visited_pc_before) = visited_pc_before {
                        if is_used && visited_pc_before != *bytecode_offset {
                            return Err(ComputeClassHashError::InvalidBytecodeSegment(
                                InvalidBytecodeSegmentError {
                                    visited_pc: visited_pc_before,
                                    segment_start: *bytecode_offset,
                                },
                            ));
                        }
                    }

                    res.push(BytecodeSegment {
                        segment_length: item_len,
                        is_used,
                        inner_structure: boxed::Box::new(current_structure),
                    });

                    *bytecode_offset += item_len;
                    total_len += item_len;
                }

                Ok((
                    BytecodeSegmentStructure::BytecodeSegmentedNode(BytecodeSegmentedNode {
                        segments: res,
                    }),
                    total_len,
                ))
            }
        }
    }
}

impl BytecodeSegmentStructure {
    fn hash(&self) -> Felt {
        match self {
            Self::BytecodeLeaf(inner) => inner.hash(),
            Self::BytecodeSegmentedNode(inner) => inner.hash(),
        }
    }
}

impl BytecodeLeaf {
    fn hash(&self) -> Felt {
        Poseidon::hash_array(&self.data)
    }
}

impl BytecodeSegmentedNode {
    fn hash(&self) -> Felt {
        let mut data = Vec::new();

        for node in self.segments.iter() {
            data.push(node.segment_length.into());
            data.push(node.inner_structure.hash());
        }

        Poseidon::hash_array(&data) + Felt::ONE
    }
}

// We need to manually implement this because `raw_value` doesn't work with `untagged`:
//   https://github.com/serde-rs/serde/issues/1183
impl<'de> Deserialize<'de> for ContractArtifact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let temp_value = serde_json::Value::deserialize(deserializer)?;
        if let Ok(value) = SierraClass::deserialize(&temp_value) {
            return Ok(Self::SierraClass(value));
        }
        if let Ok(value) = CompiledClass::deserialize(&temp_value) {
            return Ok(Self::CompiledClass(value));
        }
        if let Ok(value) = DeprecatedContractClass::deserialize(&temp_value) {
            return Ok(Self::LegacyClass(value));
        }
        Err(serde::de::Error::custom(
            "data did not match any variant of enum ContractArtifact",
        ))
    }
}

impl Serialize for PythonicHint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.id)?;
        seq.serialize_element(&self.code)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for PythonicHint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let temp_value = serde_json::Value::deserialize(deserializer)?;
        if let serde_json::Value::Array(mut array) = temp_value {
            if array.len() != 2 {
                return Err(serde::de::Error::custom("length mismatch"));
            }

            let code = array.pop().unwrap();
            let code = Vec::<String>::deserialize(code).map_err(|err| {
                serde::de::Error::custom(format!("unable to deserialize Location: {err}"))
            })?;

            let id = array.pop().unwrap();
            let id = match id {
                serde_json::Value::Number(id) => id
                    .as_u64()
                    .ok_or_else(|| serde::de::Error::custom("id value out of range"))?,
                _ => return Err(serde::de::Error::custom("unexpected value type")),
            };

            Ok(Self { id, code })
        } else {
            Err(serde::de::Error::custom("expected sequence"))
        }
    }
}

// Manually implementing this so we can put `kind` in the middle:
impl Serialize for TypedAbiEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct StructRef<'a> {
            name: &'a str,
            kind: &'static str,
            members: &'a [EventField],
        }

        #[derive(Serialize)]
        struct EnumRef<'a> {
            name: &'a str,
            kind: &'static str,
            variants: &'a [EventField],
        }

        match self {
            TypedAbiEvent::Struct(inner) => StructRef::serialize(
                &StructRef {
                    name: &inner.name,
                    kind: "struct",
                    members: &inner.members,
                },
                serializer,
            ),
            TypedAbiEvent::Enum(inner) => EnumRef::serialize(
                &EnumRef {
                    name: &inner.name,
                    kind: "enum",
                    variants: &inner.variants,
                },
                serializer,
            ),
        }
    }
}

impl Serialize for IntOrList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Int(int) => serializer.serialize_u64(*int),
            Self::List(list) => {
                let mut seq = serializer.serialize_seq(Some(list.len()))?;
                for item in list.iter() {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
        }
    }
}

impl<'de> Visitor<'de> for IntOrListVisitor {
    type Value = IntOrList;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "number or list")
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(IntOrList::Int(v))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(element) = seq.next_element::<IntOrList>()? {
            items.push(element);
        }
        Ok(IntOrList::List(items))
    }
}

impl<'de> Deserialize<'de> for IntOrList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(IntOrListVisitor)
    }
}

fn hash_sierra_entrypoints(entrypoints: &[SierraEntryPoint<Felt>]) -> Felt {
    let mut data = Vec::new();

    for entry in entrypoints.iter() {
        data.push(entry.selector);
        data.push(entry.function_idx.into());
    }

    Poseidon::hash_array(&data)
}
