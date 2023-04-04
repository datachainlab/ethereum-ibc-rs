use crate::errors::Error;
use crate::internal_prelude::*;
use ethereum_consensus::{beacon::Slot, bls::PublicKey, sync_protocol::SyncCommittee};
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::ConsensusState as RawConsensusState;
use ethereum_light_client_verifier::state::SyncCommitteeView;
use ibc::{
    core::{
        ics02_client::{
            consensus_state::ConsensusState as Ics02ConsensusState, error::ClientError,
        },
        ics23_commitment::commitment::CommitmentRoot,
    },
    timestamp::Timestamp,
};
use ibc_proto::{google::protobuf::Any as IBCAny, protobuf::Protobuf};

pub const ETHEREUM_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.ethereum.v1.ConsensusState";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    /// finalized header's slot
    pub slot: Slot,
    /// the storage root of the IBC contract
    pub storage_root: CommitmentRoot,
    /// timestamp from execution payload
    pub timestamp: u64,
    pub current_sync_committee: PublicKey,
    /// aggregate public key of next sync committee
    pub next_sync_committee: Option<PublicKey>,
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self {
            slot: Default::default(),
            storage_root: CommitmentRoot::from_bytes(Default::default()),
            timestamp: Default::default(),
            current_sync_committee: Default::default(),
            next_sync_committee: Default::default(),
        }
    }
}

impl Ics02ConsensusState for ConsensusState {
    fn root(&self) -> &CommitmentRoot {
        &self.storage_root
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.timestamp * 1_000_000_000).unwrap()
    }
}

impl Protobuf<RawConsensusState> for ConsensusState {}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(value: RawConsensusState) -> Result<Self, Self::Error> {
        let next_sync_committee = if value.next_sync_committee.len() == 0 {
            None
        } else {
            Some(PublicKey::try_from(value.next_sync_committee)?)
        };
        Ok(Self {
            slot: value.slot.into(),
            storage_root: value.storage_root.into(),
            timestamp: value.timestamp,
            current_sync_committee: PublicKey::try_from(value.current_sync_committee)?,
            next_sync_committee,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        let next_sync_committee = match value.next_sync_committee {
            Some(next_sync_committee) => next_sync_committee.0.to_vec(),
            None => Vec::new(),
        };
        Self {
            slot: value.slot.into(),
            storage_root: value.storage_root.into_vec(),
            timestamp: value.timestamp,
            current_sync_committee: value.current_sync_committee.to_vec(),
            next_sync_committee,
        }
    }
}

impl Protobuf<IBCAny> for ConsensusState {}

impl TryFrom<IBCAny> for ConsensusState {
    type Error = ClientError;

    fn try_from(raw: IBCAny) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;
        use prost::Message;

        fn decode_consensus_state<B: Buf>(buf: B) -> Result<ConsensusState, Error> {
            RawConsensusState::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            ETHEREUM_CONSENSUS_STATE_TYPE_URL => {
                decode_consensus_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(ClientError::UnknownConsensusStateType {
                consensus_state_type: raw.type_url,
            }),
        }
    }
}

impl From<ConsensusState> for IBCAny {
    fn from(consensus_state: ConsensusState) -> Self {
        Self {
            type_url: ETHEREUM_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawConsensusState>::encode_vec(&consensus_state)
                .expect("encoding to `Any` from `ConsensusState`"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedConsensusState<const SYNC_COMMITTEE_SIZE: usize> {
    state: ConsensusState,
    current_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
    next_sync_committee: Option<SyncCommittee<SYNC_COMMITTEE_SIZE>>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> TrustedConsensusState<SYNC_COMMITTEE_SIZE> {
    pub fn new(
        consensus_state: ConsensusState,
        sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
        is_next: bool,
    ) -> Result<Self, Error> {
        sync_committee.validate()?;
        if !is_next {
            return if sync_committee.aggregate_pubkey == consensus_state.current_sync_committee {
                Ok(Self {
                    state: consensus_state,
                    current_sync_committee: Some(sync_committee),
                    next_sync_committee: None,
                })
            } else {
                Err(Error::InvalidCurrentSyncCommitteeKeys(
                    sync_committee.aggregate_pubkey.clone(),
                    consensus_state.current_sync_committee,
                ))
            };
        }

        return if let Some(next_sync_committee) = consensus_state.next_sync_committee.clone() {
            if sync_committee.aggregate_pubkey == next_sync_committee {
                Ok(Self {
                    state: consensus_state,
                    current_sync_committee: None,
                    next_sync_committee: Some(sync_committee),
                })
            } else {
                Err(Error::InvalidNextSyncCommitteeKeys(
                    sync_committee.aggregate_pubkey.clone(),
                    next_sync_committee,
                ))
            }
        } else {
            Err(Error::NoNextSyncCommitteeInConsensusState)
        };
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> TrustedConsensusState<SYNC_COMMITTEE_SIZE> {
    pub fn current_sync_committee_aggregate_key(&self) -> PublicKey {
        self.state.current_sync_committee.clone()
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> SyncCommitteeView<SYNC_COMMITTEE_SIZE>
    for TrustedConsensusState<SYNC_COMMITTEE_SIZE>
{
    fn current_slot(&self) -> Slot {
        self.state.slot
    }

    fn current_sync_committee(
        &self,
    ) -> &ethereum_consensus::sync_protocol::SyncCommittee<SYNC_COMMITTEE_SIZE> {
        self.current_sync_committee.as_ref().unwrap()
    }

    fn next_sync_committee(
        &self,
    ) -> Option<&ethereum_consensus::sync_protocol::SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.next_sync_committee.as_ref()
    }
}
