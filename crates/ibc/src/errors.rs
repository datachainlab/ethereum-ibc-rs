use crate::internal_prelude::*;
use core::time::Duration;
use displaydoc::Display;
use ethereum_consensus::{
    beacon::{BeaconBlockHeader, Slot},
    bls::PublicKey,
    sync_protocol::SyncCommitteePeriod,
    types::U64,
};
use ibc::{
    core::{ics02_client::error::ClientError, ics24_host::error::ValidationError, ContextError},
    timestamp::{ParseTimestampError, Timestamp, TimestampOverflowError},
    Height,
};

#[derive(Debug, Display)]
pub enum Error {
    /// verification error: {0}
    VerificationError(ethereum_light_client_verifier::errors::Error),
    /// consensus state doesn't have next sync committee
    NoNextSyncCommitteeInConsensusState,
    /// invalid current sync committee keys: expected={0:?} actual={1:?}
    InvalidCurrentSyncCommitteeKeys(PublicKey, PublicKey),
    /// invalid next sync committee keys: expected={0:?} actual={1:?}
    InvalidNextSyncCommitteeKeys(PublicKey, PublicKey),
    /// invalid proof format error: {0}
    InvalidProofFormatError(String),
    /// rlp decode error: {0}
    RLPDecodeError(rlp::DecoderError),
    /// future period error: store={0} update={1}
    FuturePeriodError(U64, U64),
    /// both updates of misbehaviour data must have same period: {0} != {1}
    DifferentPeriodInNextSyncCommitteeMisbehaviour(SyncCommitteePeriod, SyncCommitteePeriod),
    /// both updates of misbehaviour data must have next sync committee
    NoNextSyncCommitteeInNextSyncCommitteeMisbehaviour,
    /// both updates of misbehaviour data must have different next sync committee: {0:?}
    SameNextSyncCommitteeInNextSyncCommitteeMisbehaviour(PublicKey),
    /// both updates of misbehaviour data must have same finalized slot: {0} != {1}
    DifferentSlotInFinalizedHeaderMisbehaviour(Slot, Slot),
    /// both updates of misbehaviour data must have different finalized header: {0:?}
    SameFinalizedHeaderInFinalizedHeaderMisbehaviour(BeaconBlockHeader),
    /// the height is insufficient: latest_height=`{latest_height}` target_height=`{target_height}`
    InsufficientHeight {
        latest_height: Height,
        target_height: Height,
    },
    /// unexpected timestamp: expected={0} got={1}
    UnexpectedTimestamp(u64, u64),
    /// missing trusting period
    MissingTrustingPeriod,
    /// negative max clock drift
    NegativeMaxClockDrift,
    /// out of trusting period: current_timestamp={current_timestamp} trusting_period_end={trusting_period_end}
    OutOfTrustingPeriod {
        current_timestamp: Timestamp,
        trusting_period_end: Timestamp,
    },
    /// header is coming from future: current_timestamp={current_timestamp} clock_drift={clock_drift:?} header_timestamp={header_timestamp}
    HeaderFromFuture {
        current_timestamp: Timestamp,
        clock_drift: Duration,
        header_timestamp: Timestamp,
    },
    /// ethereum consensus error: `{0}`
    EthereumConsensusError(ethereum_consensus::errors::Error),
    /// decode error: `{0}`
    Decode(prost::DecodeError),
    /// ssz deserialize error: `{0}`
    SSZDeserialize(ssz_rs::DeserializeError),
    /// ics02 error: `{0}`
    ICS02(ClientError),
    /// ics24 error: `{0}`
    ICS24(ValidationError),
    /// context error
    ContextError(ContextError),
    /// timestamp overflow error: `{0}`
    TimestampOverflowError(TimestampOverflowError),
    /// parse timestamp error: `{0}`
    ParseTimestampError(ParseTimestampError),
}

impl From<Error> for ClientError {
    fn from(value: Error) -> Self {
        ClientError::ClientSpecific {
            description: format!("{}", value),
        }
    }
}

impl From<Error> for ContextError {
    fn from(value: Error) -> Self {
        ContextError::ClientError(value.into())
    }
}

impl From<ethereum_light_client_verifier::errors::Error> for Error {
    fn from(value: ethereum_light_client_verifier::errors::Error) -> Self {
        Error::VerificationError(value)
    }
}

impl From<rlp::DecoderError> for Error {
    fn from(value: rlp::DecoderError) -> Self {
        Error::RLPDecodeError(value)
    }
}

impl From<ethereum_consensus::errors::Error> for Error {
    fn from(value: ethereum_consensus::errors::Error) -> Self {
        Error::EthereumConsensusError(value)
    }
}

impl From<ClientError> for Error {
    fn from(value: ClientError) -> Self {
        Self::ICS02(value)
    }
}

impl From<ValidationError> for Error {
    fn from(value: ValidationError) -> Self {
        Self::ICS24(value)
    }
}

impl From<ssz_rs::DeserializeError> for Error {
    fn from(value: ssz_rs::DeserializeError) -> Self {
        Self::SSZDeserialize(value)
    }
}

impl From<ContextError> for Error {
    fn from(value: ContextError) -> Self {
        Self::ContextError(value)
    }
}

impl From<TimestampOverflowError> for Error {
    fn from(value: TimestampOverflowError) -> Self {
        Self::TimestampOverflowError(value)
    }
}

impl From<ParseTimestampError> for Error {
    fn from(value: ParseTimestampError) -> Self {
        Self::ParseTimestampError(value)
    }
}
