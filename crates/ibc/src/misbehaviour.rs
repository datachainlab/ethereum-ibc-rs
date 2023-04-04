use crate::{header::TrustedSyncCommittee, update::ConsensusUpdateInfo};
use ethereum_light_client_verifier::misbehaviour::Misbehaviour as MisbehaviourData;
use ibc::core::{
    ics02_client::{error::ClientError, misbehaviour::Misbehaviour as Ics02Misbehaviour},
    ics24_host::identifier::ClientId,
};
use ibc_proto::google::protobuf::Any;
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

#[allow(unused_variables)]
impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<Any> for Misbehaviour<SYNC_COMMITTEE_SIZE> {
    type Error = ClientError;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        todo!()
    }
}
