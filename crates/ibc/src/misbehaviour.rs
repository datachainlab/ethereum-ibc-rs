use crate::{errors::Error, header::TrustedSyncCommittee, update::ConsensusUpdateInfo};
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::{
    FinalizedHeaderMisbehaviour as RawFinalizedHeaderMisbehaviour,
    NextSyncCommitteeMisbehaviour as RawNextSyncCommitteeMisbehaviour,
};
use ethereum_light_client_verifier::misbehaviour::Misbehaviour as MisbehaviourData;
use ibc::core::{
    ics02_client::{error::ClientError, misbehaviour::Misbehaviour as Ics02Misbehaviour},
    ics24_host::identifier::ClientId,
};
use ibc_proto::google::protobuf::Any as IBCAny;
use ibc_proto::protobuf::Protobuf;
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
        todo!()
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawNextSyncCommitteeMisbehaviour>
    for Misbehaviour<SYNC_COMMITTEE_SIZE>
{
    type Error = Error;
    fn try_from(value: RawNextSyncCommitteeMisbehaviour) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Misbehaviour<SYNC_COMMITTEE_SIZE>>
    for RawFinalizedHeaderMisbehaviour
{
    fn from(value: Misbehaviour<SYNC_COMMITTEE_SIZE>) -> Self {
        todo!()
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Misbehaviour<SYNC_COMMITTEE_SIZE>>
    for RawNextSyncCommitteeMisbehaviour
{
    fn from(value: Misbehaviour<SYNC_COMMITTEE_SIZE>) -> Self {
        todo!()
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<IBCAny> for Misbehaviour<SYNC_COMMITTEE_SIZE> {}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<IBCAny> for Misbehaviour<SYNC_COMMITTEE_SIZE> {
    type Error = ClientError;

    fn try_from(raw: IBCAny) -> Result<Self, Self::Error> {
        // use core::ops::Deref;

        // match raw.type_url.as_str() {
        //     ETHEREUM_HEADER_TYPE_URL => decode_header(raw.value.deref()).map_err(Into::into),
        //     _ => Err(ClientError::UnknownHeaderType {
        //         header_type: raw.type_url,
        //     }),
        // }
        todo!()
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Misbehaviour<SYNC_COMMITTEE_SIZE>> for IBCAny {
    fn from(value: Misbehaviour<SYNC_COMMITTEE_SIZE>) -> Self {
        // Self {
        //     type_url: ETHEREUM_HEADER_TYPE_URL.to_string(),
        //     value: Protobuf::<RawHeader>::encode_vec(&header)
        //         .expect("encoding to `Any` from `TmHeader`"),
        // }
        todo!()
    }
}
