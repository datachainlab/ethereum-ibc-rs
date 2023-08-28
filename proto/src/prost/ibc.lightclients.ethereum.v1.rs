#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientState {
    #[prost(bytes = "vec", tag = "1")]
    pub genesis_validators_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub min_sync_committee_participants: u64,
    #[prost(uint64, tag = "3")]
    pub genesis_time: u64,
    #[prost(message, optional, tag = "4")]
    pub fork_parameters: ::core::option::Option<ForkParameters>,
    #[prost(uint64, tag = "5")]
    pub seconds_per_slot: u64,
    #[prost(uint64, tag = "6")]
    pub slots_per_epoch: u64,
    #[prost(uint64, tag = "7")]
    pub epochs_per_sync_committee_period: u64,
    #[prost(bytes = "vec", tag = "8")]
    pub ibc_address: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub ibc_commitments_slot: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "10")]
    pub trust_level: ::core::option::Option<Fraction>,
    #[prost(message, optional, tag = "11")]
    pub trusting_period: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(message, optional, tag = "12")]
    pub max_clock_drift: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(uint64, tag = "13")]
    pub latest_slot: u64,
    #[prost(uint64, tag = "14")]
    pub latest_execution_block_number: u64,
    #[prost(message, optional, tag = "15")]
    pub frozen_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusState {
    #[prost(uint64, tag = "1")]
    pub slot: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub storage_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub timestamp: ::core::option::Option<
        super::super::super::super::google::protobuf::Timestamp,
    >,
    #[prost(bytes = "vec", tag = "4")]
    pub current_sync_committee: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub next_sync_committee: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Header {
    #[prost(message, optional, tag = "1")]
    pub trusted_sync_committee: ::core::option::Option<TrustedSyncCommittee>,
    #[prost(message, optional, tag = "2")]
    pub consensus_update: ::core::option::Option<LightClientUpdate>,
    #[prost(message, optional, tag = "3")]
    pub execution_update: ::core::option::Option<ExecutionUpdate>,
    #[prost(message, optional, tag = "4")]
    pub account_update: ::core::option::Option<AccountUpdate>,
    /// seconds from unix epoch
    #[prost(uint64, tag = "5")]
    pub timestamp: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TrustedSyncCommittee {
    #[prost(message, optional, tag = "1")]
    pub trusted_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(message, optional, tag = "2")]
    pub sync_committee: ::core::option::Option<SyncCommittee>,
    #[prost(bool, tag = "3")]
    pub is_next: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ForkParameters {
    #[prost(bytes = "vec", tag = "1")]
    pub genesis_fork_version: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub forks: ::prost::alloc::vec::Vec<Fork>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fraction {
    #[prost(uint64, tag = "1")]
    pub numerator: u64,
    #[prost(uint64, tag = "2")]
    pub denominator: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fork {
    #[prost(bytes = "vec", tag = "1")]
    pub version: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LightClientUpdate {
    #[prost(message, optional, tag = "1")]
    pub attested_header: ::core::option::Option<BeaconBlockHeader>,
    #[prost(message, optional, tag = "2")]
    pub next_sync_committee: ::core::option::Option<SyncCommittee>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub next_sync_committee_branch: ::prost::alloc::vec::Vec<
        ::prost::alloc::vec::Vec<u8>,
    >,
    #[prost(message, optional, tag = "4")]
    pub finalized_header: ::core::option::Option<BeaconBlockHeader>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub finalized_header_branch: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "6")]
    pub finalized_execution_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "7")]
    pub finalized_execution_branch: ::prost::alloc::vec::Vec<
        ::prost::alloc::vec::Vec<u8>,
    >,
    #[prost(message, optional, tag = "8")]
    pub sync_aggregate: ::core::option::Option<SyncAggregate>,
    #[prost(uint64, tag = "9")]
    pub signature_slot: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncCommittee {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub pubkeys: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "2")]
    pub aggregate_pubkey: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncAggregate {
    #[prost(bytes = "vec", tag = "1")]
    pub sync_committee_bits: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub sync_committee_signature: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionUpdate {
    #[prost(bytes = "vec", tag = "1")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub state_root_branch: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, tag = "3")]
    pub block_number: u64,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub block_number_branch: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountUpdate {
    #[prost(bytes = "vec", tag = "1")]
    pub account_proof: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub account_storage_root: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BeaconBlockHeader {
    #[prost(uint64, tag = "1")]
    pub slot: u64,
    #[prost(uint64, tag = "2")]
    pub proposer_index: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub parent_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub body_root: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizedHeaderMisbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub trusted_sync_committee: ::core::option::Option<TrustedSyncCommittee>,
    #[prost(message, optional, tag = "3")]
    pub consensus_update_1: ::core::option::Option<LightClientUpdate>,
    #[prost(message, optional, tag = "4")]
    pub consensus_update_2: ::core::option::Option<LightClientUpdate>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NextSyncCommitteeMisbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub trusted_sync_committee: ::core::option::Option<TrustedSyncCommittee>,
    #[prost(message, optional, tag = "3")]
    pub consensus_update_1: ::core::option::Option<LightClientUpdate>,
    #[prost(message, optional, tag = "4")]
    pub consensus_update_2: ::core::option::Option<LightClientUpdate>,
}
