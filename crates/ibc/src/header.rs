use crate::errors::Error;
use crate::internal_prelude::*;
use crate::misbehaviour::Misbehaviour;
use crate::types::{
    convert_consensus_update_to_proto, convert_execution_update_to_proto,
    convert_proto_to_consensus_update, convert_proto_to_execution_update, AccountUpdateInfo,
    TrustedSyncCommittee,
};
use crate::update::{ConsensusUpdateInfo, ExecutionUpdateInfo};
use bytes::Buf;
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::Header as RawHeader;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::header::Header as Ics02Header;
use ibc::timestamp::Timestamp;
use ibc_proto::google::protobuf::Any as IBCAny;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

pub const ETHEREUM_HEADER_TYPE_URL: &str = "/ibc.lightclients.ethereum.v1.Header";

#[allow(clippy::large_enum_variant)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum ClientMessage<const SYNC_COMMITTEE_SIZE: usize> {
    Header(Header<SYNC_COMMITTEE_SIZE>),
    Misbehaviour(Misbehaviour<SYNC_COMMITTEE_SIZE>),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Header<const SYNC_COMMITTEE_SIZE: usize> {
    pub trusted_sync_committee: TrustedSyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    pub execution_update: ExecutionUpdateInfo,
    pub account_update: AccountUpdateInfo,
    pub timestamp: Timestamp,
}

pub fn decode_header<const SYNC_COMMITTEE_SIZE: usize, B: Buf>(
    buf: B,
) -> Result<Header<SYNC_COMMITTEE_SIZE>, Error> {
    RawHeader::decode(buf).map_err(Error::Decode)?.try_into()
}

impl<const SYNC_COMMITTEE_SIZE: usize> Ics02Header for Header<SYNC_COMMITTEE_SIZE> {
    fn height(&self) -> ibc::Height {
        ibc::Height::new(0, self.execution_update.block_number.into()).unwrap()
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<RawHeader> for Header<SYNC_COMMITTEE_SIZE> {}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawHeader> for Header<SYNC_COMMITTEE_SIZE> {
    type Error = Error;
    fn try_from(value: RawHeader) -> Result<Self, Self::Error> {
        let trusted_sync_committee = value.trusted_sync_committee.unwrap();
        let consensus_update = value.consensus_update.unwrap();
        let execution_update = value.execution_update.unwrap();
        let account_update = value.account_update.unwrap();

        Ok(Self {
            trusted_sync_committee: trusted_sync_committee.try_into()?,
            consensus_update: convert_proto_to_consensus_update(consensus_update)?,
            execution_update: convert_proto_to_execution_update(execution_update),
            account_update: account_update.try_into()?,
            timestamp: Timestamp::from_nanoseconds(
                value.timestamp.checked_mul(1_000_000_000).ok_or_else(|| {
                    Error::TimestampOverflowError(
                        ibc::timestamp::TimestampOverflowError::TimestampOverflow,
                    )
                })?,
            )?,
        })
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Header<SYNC_COMMITTEE_SIZE>> for RawHeader {
    fn from(value: Header<SYNC_COMMITTEE_SIZE>) -> Self {
        let consensus_update = value.consensus_update;
        let execution_update = value.execution_update;
        let account_update = value.account_update;

        Self {
            trusted_sync_committee: Some(value.trusted_sync_committee.into()),
            consensus_update: Some(convert_consensus_update_to_proto(consensus_update)),
            execution_update: Some(convert_execution_update_to_proto(execution_update)),
            account_update: Some(account_update.into()),
            timestamp: value.timestamp.nanoseconds() / 1_000_000_000,
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<IBCAny> for Header<SYNC_COMMITTEE_SIZE> {}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<IBCAny> for Header<SYNC_COMMITTEE_SIZE> {
    type Error = ClientError;

    fn try_from(raw: IBCAny) -> Result<Self, Self::Error> {
        use core::ops::Deref;

        match raw.type_url.as_str() {
            ETHEREUM_HEADER_TYPE_URL => decode_header(raw.value.deref()).map_err(Into::into),
            _ => Err(ClientError::UnknownHeaderType {
                header_type: raw.type_url,
            }),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Header<SYNC_COMMITTEE_SIZE>> for IBCAny {
    fn from(header: Header<SYNC_COMMITTEE_SIZE>) -> Self {
        Self {
            type_url: ETHEREUM_HEADER_TYPE_URL.to_string(),
            value: Protobuf::<RawHeader>::encode_vec(&header)
                .expect("encoding to `Any` from `TmHeader`"),
        }
    }
}
