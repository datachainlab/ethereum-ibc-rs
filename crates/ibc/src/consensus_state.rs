use crate::errors::Error;
use crate::internal_prelude::*;
use ethereum_consensus::{
    beacon::Slot,
    bls::PublicKey,
    compute::compute_sync_committee_period_at_slot,
    context::ChainContext,
    sync_protocol::{SyncCommittee, SyncCommitteePeriod},
};
use ethereum_ibc_proto::{
    google::protobuf::Timestamp as ProtoTimestamp,
    ibc::lightclients::ethereum::v1::ConsensusState as RawConsensusState,
};
use ethereum_light_client_verifier::{state::LightClientStoreReader, updates::ConsensusUpdate};
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
    pub timestamp: Timestamp,
    /// aggregate public key of current sync committee
    pub current_sync_committee: PublicKey,
    /// aggregate public key of next sync committee
    pub next_sync_committee: PublicKey,
}

impl ConsensusState {
    pub fn validate(&self) -> Result<(), Error> {
        if self.slot == Default::default() {
            Err(Error::UninitializedConsensusStateField("slot"))
        } else if self.storage_root.as_bytes().is_empty() {
            Err(Error::UninitializedConsensusStateField("storage_root"))
        } else if self.timestamp == Timestamp::default() {
            Err(Error::UninitializedConsensusStateField("timestamp"))
        } else if self.current_sync_committee == PublicKey::default() {
            Err(Error::UninitializedConsensusStateField(
                "current_sync_committee",
            ))
        } else {
            Ok(())
        }
    }

    pub fn current_period<C: ChainContext>(&self, ctx: &C) -> SyncCommitteePeriod {
        compute_sync_committee_period_at_slot(ctx, self.slot)
    }
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
        self.timestamp
    }
}

impl Protobuf<RawConsensusState> for ConsensusState {}

fn proto_timestamp_to_ibc_timestamp(timestamp: ProtoTimestamp) -> Result<Timestamp, Error> {
    use ibc::timestamp::TimestampOverflowError::TimestampOverflow;
    if timestamp.seconds < 0 || timestamp.nanos < 0 {
        return Err(Error::InvalidRawConsensusState {
            reason: "timestamp seconds or nanos is negative".to_string(),
        });
    }
    let nanos = (timestamp.seconds as u64)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| Error::TimestampOverflowError(TimestampOverflow))?
        .checked_add(timestamp.nanos as u64)
        .ok_or_else(|| Error::TimestampOverflowError(TimestampOverflow))?;
    Ok(Timestamp::from_nanoseconds(nanos)?)
}

fn ibc_timestamp_to_proto_timestamp(timestamp: Timestamp) -> ProtoTimestamp {
    let nanos = timestamp.nanoseconds();
    ProtoTimestamp {
        seconds: (nanos / 1_000_000_000) as i64,
        nanos: (nanos % 1_000_000_000) as i32,
    }
}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(value: RawConsensusState) -> Result<Self, Self::Error> {
        let next_sync_committee = if value.next_sync_committee.is_empty() {
            return Err(Self::Error::InvalidRawConsensusState {
                reason: "next_sync_committee is empty".to_string(),
            });
        } else {
            PublicKey::try_from(value.next_sync_committee)?
        };
        Ok(Self {
            slot: value.slot.into(),
            storage_root: value.storage_root.into(),
            timestamp: proto_timestamp_to_ibc_timestamp(value.timestamp.ok_or_else(|| {
                Self::Error::InvalidRawConsensusState {
                    reason: "timestamp is none".to_string(),
                }
            })?)?,
            current_sync_committee: PublicKey::try_from(value.current_sync_committee)?,
            next_sync_committee,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        Self {
            slot: value.slot.into(),
            storage_root: value.storage_root.into_vec(),
            timestamp: Some(ibc_timestamp_to_proto_timestamp(value.timestamp)),
            current_sync_committee: value.current_sync_committee.to_vec(),
            next_sync_committee: value.next_sync_committee.to_vec(),
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
                    sync_committee.aggregate_pubkey,
                    consensus_state.current_sync_committee,
                ))
            };
        }

        if sync_committee.aggregate_pubkey == consensus_state.next_sync_committee {
            Ok(Self {
                state: consensus_state,
                current_sync_committee: None,
                next_sync_committee: Some(sync_committee),
            })
        } else {
            Err(Error::InvalidNextSyncCommitteeKeys(
                sync_committee.aggregate_pubkey,
                consensus_state.next_sync_committee,
            ))
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> LightClientStoreReader<SYNC_COMMITTEE_SIZE>
    for TrustedConsensusState<SYNC_COMMITTEE_SIZE>
{
    fn current_period<C: ChainContext>(&self, ctx: &C) -> SyncCommitteePeriod {
        self.state.current_period(ctx)
    }

    fn current_sync_committee(&self) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.current_sync_committee.clone()
    }

    fn next_sync_committee(&self) -> Option<SyncCommittee<SYNC_COMMITTEE_SIZE>> {
        self.next_sync_committee.clone()
    }

    fn ensure_relevant_update<CC: ChainContext, C: ConsensusUpdate<SYNC_COMMITTEE_SIZE>>(
        &self,
        _ctx: &CC,
        update: &C,
    ) -> Result<(), ethereum_light_client_verifier::errors::Error> {
        if self.state.slot >= update.finalized_beacon_header().slot {
            Err(
                ethereum_light_client_verifier::errors::Error::IrrelevantConsensusUpdates(
                    "finalized header slot is not greater than current slot".to_string(),
                ),
            )
        } else {
            Ok(())
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<TrustedConsensusState<SYNC_COMMITTEE_SIZE>>
    for ConsensusState
{
    fn from(value: TrustedConsensusState<SYNC_COMMITTEE_SIZE>) -> Self {
        value.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn test_timestamp() {
        {
            // nanos is non-zero
            let it1 = Timestamp::from_nanoseconds(
                datetime!(2023-08-20 0:00 UTC).unix_timestamp_nanos() as u64 - 1,
            )
            .unwrap();
            let pt1 = ibc_timestamp_to_proto_timestamp(it1);
            let it2 = proto_timestamp_to_ibc_timestamp(pt1).unwrap();
            assert_eq!(it1, it2);
        }

        {
            // nanos is zero
            let it1 = Timestamp::from_nanoseconds(
                datetime!(2023-08-20 0:00 UTC).unix_timestamp_nanos() as u64,
            )
            .unwrap();
            let pt1 = ibc_timestamp_to_proto_timestamp(it1);
            let it2 = proto_timestamp_to_ibc_timestamp(pt1).unwrap();
            assert_eq!(it1, it2);
        }
    }
}
