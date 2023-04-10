use crate::{
    errors::Error,
    types::{
        convert_consensus_update_to_proto, convert_proto_to_consensus_update, TrustedSyncCommittee,
    },
    update::ConsensusUpdateInfo,
};
use alloc::string::ToString;
use bytes::Buf;
use core::str::FromStr;
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::{
    FinalizedHeaderMisbehaviour as RawFinalizedHeaderMisbehaviour,
    NextSyncCommitteeMisbehaviour as RawNextSyncCommitteeMisbehaviour,
};
use ethereum_light_client_verifier::misbehaviour::{
    FinalizedHeaderMisbehaviour, Misbehaviour as MisbehaviourData, NextSyncCommitteeMisbehaviour,
};
use ibc::core::{
    ics02_client::{error::ClientError, misbehaviour::Misbehaviour as Ics02Misbehaviour},
    ics24_host::identifier::ClientId,
};
use ibc_proto::google::protobuf::Any as IBCAny;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use serde::{Deserialize, Serialize};

pub const ETHEREUM_FINALIZED_HEADER_MISBEHAVIOUR_TYPE_URL: &str =
    "/ibc.lightclients.ethereum.v1.FinalizedHeaderMisbehaviour";
pub const ETHEREUM_NEXT_SYNC_COMMITTEE_MISBEHAVIOUR_TYPE_URL: &str =
    "/ibc.lightclients.ethereum.v1.NextSyncCommitteeMisbehaviour";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Misbehaviour<const SYNC_COMMITTEE_SIZE: usize> {
    pub client_id: ClientId,
    pub trusted_sync_committee: TrustedSyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub data: MisbehaviourData<SYNC_COMMITTEE_SIZE, ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> Ics02Misbehaviour for Misbehaviour<SYNC_COMMITTEE_SIZE> {
    fn client_id(&self) -> &ibc::core::ics24_host::identifier::ClientId {
        &self.client_id
    }

    fn height(&self) -> ibc::Height {
        self.trusted_sync_committee.height
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<RawFinalizedHeaderMisbehaviour>
    for Misbehaviour<SYNC_COMMITTEE_SIZE>
{
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<RawNextSyncCommitteeMisbehaviour>
    for Misbehaviour<SYNC_COMMITTEE_SIZE>
{
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawFinalizedHeaderMisbehaviour>
    for Misbehaviour<SYNC_COMMITTEE_SIZE>
{
    type Error = Error;
    fn try_from(value: RawFinalizedHeaderMisbehaviour) -> Result<Self, Self::Error> {
        Ok(Self {
            client_id: ClientId::from_str(&value.client_id)?,
            trusted_sync_committee: value.trusted_sync_committee.unwrap().try_into()?,
            data: MisbehaviourData::FinalizedHeader(FinalizedHeaderMisbehaviour {
                consensus_update_1: convert_proto_to_consensus_update(
                    value.consensus_update_1.unwrap(),
                )?,
                consensus_update_2: convert_proto_to_consensus_update(
                    value.consensus_update_2.unwrap(),
                )?,
            }),
        })
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawNextSyncCommitteeMisbehaviour>
    for Misbehaviour<SYNC_COMMITTEE_SIZE>
{
    type Error = Error;
    fn try_from(value: RawNextSyncCommitteeMisbehaviour) -> Result<Self, Self::Error> {
        Ok(Self {
            client_id: ClientId::from_str(&value.client_id)?,
            trusted_sync_committee: value.trusted_sync_committee.unwrap().try_into()?,
            data: MisbehaviourData::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                consensus_update_1: convert_proto_to_consensus_update(
                    value.consensus_update_1.unwrap(),
                )?,
                consensus_update_2: convert_proto_to_consensus_update(
                    value.consensus_update_2.unwrap(),
                )?,
            }),
        })
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Misbehaviour<SYNC_COMMITTEE_SIZE>>
    for RawFinalizedHeaderMisbehaviour
{
    fn from(value: Misbehaviour<SYNC_COMMITTEE_SIZE>) -> Self {
        let data = match value.data {
            MisbehaviourData::FinalizedHeader(data) => data,
            _ => panic!("unexpected misbehaviour type"),
        };
        Self {
            client_id: value.client_id.as_str().to_string(),
            trusted_sync_committee: Some(value.trusted_sync_committee.into()),
            consensus_update_1: Some(convert_consensus_update_to_proto(data.consensus_update_1)),
            consensus_update_2: Some(convert_consensus_update_to_proto(data.consensus_update_2)),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Misbehaviour<SYNC_COMMITTEE_SIZE>>
    for RawNextSyncCommitteeMisbehaviour
{
    fn from(value: Misbehaviour<SYNC_COMMITTEE_SIZE>) -> Self {
        let data = match value.data {
            MisbehaviourData::NextSyncCommittee(data) => data,
            _ => panic!("unexpected misbehaviour type"),
        };
        Self {
            client_id: value.client_id.as_str().to_string(),
            trusted_sync_committee: Some(value.trusted_sync_committee.into()),
            consensus_update_1: Some(convert_consensus_update_to_proto(data.consensus_update_1)),
            consensus_update_2: Some(convert_consensus_update_to_proto(data.consensus_update_2)),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<IBCAny> for Misbehaviour<SYNC_COMMITTEE_SIZE> {}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<IBCAny> for Misbehaviour<SYNC_COMMITTEE_SIZE> {
    type Error = ClientError;

    fn try_from(raw: IBCAny) -> Result<Self, Self::Error> {
        use core::ops::Deref;

        match raw.type_url.as_str() {
            ETHEREUM_FINALIZED_HEADER_MISBEHAVIOUR_TYPE_URL => {
                decode_finalized_header_misbehaviour(raw.value.deref()).map_err(Into::into)
            }
            ETHEREUM_NEXT_SYNC_COMMITTEE_MISBEHAVIOUR_TYPE_URL => {
                decode_next_sync_committee_misbehaviour(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(ClientError::UnknownMisbehaviourType {
                misbehaviour_type: raw.type_url,
            }),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Misbehaviour<SYNC_COMMITTEE_SIZE>> for IBCAny {
    fn from(value: Misbehaviour<SYNC_COMMITTEE_SIZE>) -> Self {
        match value.data {
            MisbehaviourData::FinalizedHeader(_) => Self {
                type_url: ETHEREUM_FINALIZED_HEADER_MISBEHAVIOUR_TYPE_URL.to_string(),
                value: Protobuf::<RawFinalizedHeaderMisbehaviour>::encode_vec(&value)
                    .expect("encoding to `Any` from `TmHeader`"),
            },
            MisbehaviourData::NextSyncCommittee(_) => Self {
                type_url: ETHEREUM_NEXT_SYNC_COMMITTEE_MISBEHAVIOUR_TYPE_URL.to_string(),
                value: Protobuf::<RawNextSyncCommitteeMisbehaviour>::encode_vec(&value)
                    .expect("encoding to `Any` from `TmHeader`"),
            },
        }
    }
}

fn decode_finalized_header_misbehaviour<const SYNC_COMMITTEE_SIZE: usize, B: Buf>(
    buf: B,
) -> Result<Misbehaviour<SYNC_COMMITTEE_SIZE>, Error> {
    RawFinalizedHeaderMisbehaviour::decode(buf)
        .map_err(Error::Decode)?
        .try_into()
}

fn decode_next_sync_committee_misbehaviour<const SYNC_COMMITTEE_SIZE: usize, B: Buf>(
    buf: B,
) -> Result<Misbehaviour<SYNC_COMMITTEE_SIZE>, Error> {
    RawNextSyncCommitteeMisbehaviour::decode(buf)
        .map_err(Error::Decode)?
        .try_into()
}
