use crate::{
    errors::Error,
    types::{
        convert_consensus_update_to_proto, convert_proto_to_consensus_update, ConsensusUpdateInfo,
        TrustedSyncCommittee,
    },
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
            trusted_sync_committee: value
                .trusted_sync_committee
                .ok_or(Error::proto_missing("trusted_sync_committee"))?
                .try_into()?,
            data: MisbehaviourData::FinalizedHeader(FinalizedHeaderMisbehaviour {
                consensus_update_1: convert_proto_to_consensus_update(
                    value
                        .consensus_update_1
                        .ok_or(Error::proto_missing("consensus_update_1"))?,
                )?,
                consensus_update_2: convert_proto_to_consensus_update(
                    value
                        .consensus_update_2
                        .ok_or(Error::proto_missing("consensus_update_2"))?,
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
            trusted_sync_committee: value
                .trusted_sync_committee
                .ok_or(Error::proto_missing("trusted_sync_committee"))?
                .try_into()?,
            data: MisbehaviourData::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                consensus_update_1: convert_proto_to_consensus_update(
                    value
                        .consensus_update_1
                        .ok_or(Error::proto_missing("consensus_update_1"))?,
                )?,
                consensus_update_2: convert_proto_to_consensus_update(
                    value
                        .consensus_update_2
                        .ok_or(Error::proto_missing("consensus_update_2"))?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth_client_type;
    use ethereum_consensus::context::ChainContext;
    use ethereum_consensus::{config, types::U64};
    use ethereum_light_client_verifier::{
        consensus::test_utils::{gen_light_client_update_with_params, MockSyncCommitteeManager},
        context::{Fraction, LightClientContext},
        updates::ConsensusUpdateInfo as EthConsensusUpdateInfo,
    };
    use std::time::SystemTime;

    #[test]
    fn test_mibehaviour_conversion() {
        let scm = MockSyncCommitteeManager::<32>::new(1, 4);
        let ctx = LightClientContext::new_with_config(
            config::minimal::get_config(),
            Default::default(),
            Default::default(),
            Fraction::new(2, 3),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .into(),
        );
        let period_1 = U64(1) * ctx.slots_per_epoch() * ctx.epochs_per_sync_committee_period();

        let current_sync_committee = scm.get_committee(1);
        let base_signature_slot = period_1 + 11;
        let base_attested_slot = base_signature_slot - 1;
        let base_finalized_epoch = base_attested_slot / ctx.slots_per_epoch();
        let dummy_execution_state_root = [1u8; 32].into();
        let dummy_execution_block_number = 1;

        let update_1 = gen_light_client_update_with_params::<32, _>(
            &ctx,
            base_signature_slot,
            base_attested_slot,
            base_finalized_epoch,
            dummy_execution_state_root,
            dummy_execution_block_number.into(),
            current_sync_committee,
            scm.get_committee(2),
            32,
        );
        let update_2 = gen_light_client_update_with_params::<32, _>(
            &ctx,
            base_signature_slot,
            base_attested_slot,
            base_finalized_epoch,
            dummy_execution_state_root,
            dummy_execution_block_number.into(),
            current_sync_committee,
            scm.get_committee(3),
            32,
        );
        let update_1 = to_consensus_update_info(update_1);
        let update_2 = to_consensus_update_info(update_2);
        let misbehaviour = Misbehaviour {
            client_id: ClientId::new(eth_client_type(), 0).unwrap(),
            trusted_sync_committee: TrustedSyncCommittee {
                height: ibc::Height::new(1, 1).unwrap(),
                sync_committee: current_sync_committee.to_committee().clone(),
                is_next: true,
            },
            data: MisbehaviourData::NextSyncCommittee(NextSyncCommitteeMisbehaviour {
                consensus_update_1: update_1.clone(),
                consensus_update_2: update_2.clone(),
            }),
        };
        let any = IBCAny::from(misbehaviour.clone());
        let decoded = Misbehaviour::<32>::try_from(any).unwrap();
        assert_eq!(misbehaviour, decoded);

        let different_dummy_execution_state_root = [2u8; 32].into();
        let update_3 = gen_light_client_update_with_params::<32, _>(
            &ctx,
            base_signature_slot,
            base_attested_slot,
            base_finalized_epoch,
            different_dummy_execution_state_root,
            dummy_execution_block_number.into(),
            current_sync_committee,
            scm.get_committee(2),
            32,
        );

        let update_3 = to_consensus_update_info(update_3);
        let misbehaviour = Misbehaviour {
            client_id: ClientId::new(eth_client_type(), 0).unwrap(),
            trusted_sync_committee: TrustedSyncCommittee {
                height: ibc::Height::new(1, 1).unwrap(),
                sync_committee: current_sync_committee.to_committee().clone(),
                is_next: true,
            },
            data: MisbehaviourData::FinalizedHeader(FinalizedHeaderMisbehaviour {
                consensus_update_1: update_1.clone(),
                consensus_update_2: update_3.clone(),
            }),
        };
        let any = IBCAny::from(misbehaviour.clone());
        let decoded = Misbehaviour::<32>::try_from(any).unwrap();
        assert_eq!(misbehaviour, decoded);
    }

    fn to_consensus_update_info<const SYNC_COMMITTEE_SIZE: usize>(
        consensus_update: EthConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    ) -> ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE> {
        ConsensusUpdateInfo {
            attested_header: consensus_update.light_client_update.attested_header,
            next_sync_committee: consensus_update.light_client_update.next_sync_committee,
            finalized_header: consensus_update.light_client_update.finalized_header,
            sync_aggregate: consensus_update.light_client_update.sync_aggregate,
            signature_slot: consensus_update.light_client_update.signature_slot,
            finalized_execution_root: consensus_update.finalized_execution_root,
            finalized_execution_branch: consensus_update.finalized_execution_branch,
        }
    }
}
