use crate::errors::Error;
use crate::internal_prelude::*;
use crate::misbehaviour::{
    Misbehaviour, ETHEREUM_FINALIZED_HEADER_MISBEHAVIOUR_TYPE_URL,
    ETHEREUM_NEXT_SYNC_COMMITTEE_MISBEHAVIOUR_TYPE_URL,
};
use crate::types::{
    convert_consensus_update_to_proto, convert_execution_update_to_proto,
    convert_proto_to_consensus_update, convert_proto_to_execution_update, AccountUpdateInfo,
    ConsensusUpdateInfo, ExecutionUpdateInfo, TrustedSyncCommittee,
};
use bytes::Buf;
use ethereum_consensus::compute::compute_timestamp_at_slot;
use ethereum_consensus::context::ChainContext;
use ethereum_consensus::types::U64;
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::Header as RawHeader;
use ethereum_light_client_verifier::updates::ConsensusUpdate;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::header::Header as Ics02Header;
use ibc::timestamp::Timestamp;
use ibc_proto::google::protobuf::Any as IBCAny;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

pub const ETHEREUM_HEADER_TYPE_URL: &str = "/ibc.lightclients.ethereum.v1.Header";

#[allow(clippy::large_enum_variant)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum ClientMessage<const SYNC_COMMITTEE_SIZE: usize> {
    Header(Header<SYNC_COMMITTEE_SIZE>),
    Misbehaviour(Misbehaviour<SYNC_COMMITTEE_SIZE>),
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<IBCAny> for ClientMessage<SYNC_COMMITTEE_SIZE> {}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<IBCAny> for ClientMessage<SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(raw: IBCAny) -> Result<Self, Self::Error> {
        match raw.type_url.as_str() {
            ETHEREUM_HEADER_TYPE_URL => {
                let header = Header::<SYNC_COMMITTEE_SIZE>::try_from(raw)?;
                Ok(Self::Header(header))
            }
            ETHEREUM_FINALIZED_HEADER_MISBEHAVIOUR_TYPE_URL
            | ETHEREUM_NEXT_SYNC_COMMITTEE_MISBEHAVIOUR_TYPE_URL => {
                let misbehaviour = Misbehaviour::<SYNC_COMMITTEE_SIZE>::try_from(raw)?;
                Ok(Self::Misbehaviour(misbehaviour))
            }
            _ => Err(Error::UnknownMessageType(raw.type_url)),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<ClientMessage<SYNC_COMMITTEE_SIZE>> for IBCAny {
    fn from(msg: ClientMessage<SYNC_COMMITTEE_SIZE>) -> Self {
        match msg {
            ClientMessage::Header(header) => IBCAny::from(header),
            ClientMessage::Misbehaviour(misbehaviour) => IBCAny::from(misbehaviour),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Header<const SYNC_COMMITTEE_SIZE: usize> {
    /// trusted sync committee corresponding to the period of the signature slot of the `consensus_update`
    pub trusted_sync_committee: TrustedSyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// consensus update attested by the `trusted_sync_committee`
    pub consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    /// execution update based on the `consensus_update.finalized_header`
    pub execution_update: ExecutionUpdateInfo,
    /// account update based on the `execution_update.state_root`
    pub account_update: AccountUpdateInfo,
    /// timestamp of the `consensus_update.finalized_header`
    pub timestamp: Timestamp,
}

pub fn decode_header<const SYNC_COMMITTEE_SIZE: usize, B: Buf>(
    buf: B,
) -> Result<Header<SYNC_COMMITTEE_SIZE>, Error> {
    RawHeader::decode(buf).map_err(Error::Decode)?.try_into()
}

impl<const SYNC_COMMITTEE_SIZE: usize> Header<SYNC_COMMITTEE_SIZE> {
    pub fn validate<C: ChainContext>(&self, ctx: &C) -> Result<(), Error> {
        self.trusted_sync_committee.validate()?;
        if self.timestamp.into_tm_time().is_none() {
            return Err(Error::ZeroTimestampError);
        }
        if self.execution_update.block_number == U64(0) {
            return Err(Error::ZeroBlockNumberError);
        }
        let header_timestamp_nanos = self
            .timestamp
            .into_tm_time()
            .unwrap()
            .unix_timestamp_nanos();
        let timestamp_secs =
            compute_timestamp_at_slot(ctx, self.consensus_update.finalized_beacon_header().slot);
        let timestamp_nanos = i128::from(timestamp_secs.0)
            .checked_mul(1_000_000_000)
            .ok_or_else(|| {
                Error::TimestampOverflowError(
                    ibc::timestamp::TimestampOverflowError::TimestampOverflow,
                )
            })?;
        if header_timestamp_nanos != timestamp_nanos {
            return Err(Error::UnexpectedTimestamp(
                timestamp_nanos,
                header_timestamp_nanos,
            ));
        }
        Ok(())
    }
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
        let trusted_sync_committee = value
            .trusted_sync_committee
            .ok_or(Error::proto_missing("trusted_sync_committee"))?;
        let consensus_update = value
            .consensus_update
            .ok_or(Error::proto_missing("consensus_update"))?;
        let execution_update = value
            .execution_update
            .ok_or(Error::proto_missing("execution_update"))?;
        let account_update = value
            .account_update
            .ok_or(Error::proto_missing("account_update"))?;
        let timestamp = Timestamp::from_nanoseconds(
            value.timestamp.checked_mul(1_000_000_000).ok_or_else(|| {
                Error::TimestampOverflowError(
                    ibc::timestamp::TimestampOverflowError::TimestampOverflow,
                )
            })?,
        )?;
        if timestamp.into_datetime().is_none() {
            return Err(Error::ZeroTimestampError);
        }
        Ok(Self {
            trusted_sync_committee: trusted_sync_committee.try_into()?,
            consensus_update: convert_proto_to_consensus_update(consensus_update)?,
            execution_update: convert_proto_to_execution_update(execution_update),
            account_update: account_update.try_into()?,
            timestamp,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_state::ETHEREUM_CLIENT_REVISION_NUMBER;
    use ethereum_consensus::context::ChainContext;
    use ethereum_consensus::{config, types::U64};
    use ethereum_light_client_verifier::{
        consensus::test_utils::{gen_light_client_update_with_params, MockSyncCommitteeManager},
        context::{Fraction, LightClientContext},
        updates::ConsensusUpdateInfo as EthConsensusUpdateInfo,
    };
    use std::time::SystemTime;

    #[test]
    fn test_header_conversion() {
        let scm = MockSyncCommitteeManager::<32>::new(1, 4);
        let ctx = LightClientContext::new_with_config(
            config::minimal::get_config(),
            Default::default(),
            Default::default(),
            Fraction::new(2, 3).unwrap(),
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

        for b in [false, true] {
            let (update, _) = gen_light_client_update_with_params::<32, _>(
                &ctx,
                base_signature_slot,
                base_attested_slot,
                base_finalized_epoch,
                dummy_execution_state_root,
                dummy_execution_block_number.into(),
                current_sync_committee,
                scm.get_committee(2),
                b,
                32,
            );
            let update = to_consensus_update_info(update);
            let header = Header {
                trusted_sync_committee: TrustedSyncCommittee {
                    height: ibc::Height::new(ETHEREUM_CLIENT_REVISION_NUMBER, 1).unwrap(),
                    sync_committee: current_sync_committee.to_committee().clone(),
                    is_next: true,
                },
                consensus_update: update.clone(),
                execution_update: ExecutionUpdateInfo {
                    block_number: U64(2),
                    ..Default::default()
                },
                account_update: AccountUpdateInfo::default(),
                timestamp: Timestamp::from_nanoseconds(
                    compute_timestamp_at_slot(&ctx, update.finalized_beacon_header().slot).0
                        * 1_000_000_000,
                )
                .unwrap(),
            };
            let res = header.validate(&ctx);
            assert!(res.is_ok(), "header validation failed: {:?}", res);
            let any = IBCAny::from(header.clone());
            let decoded = Header::<32>::try_from(any).unwrap();
            assert_eq!(header, decoded);

            let header = Header {
                trusted_sync_committee: TrustedSyncCommittee {
                    height: ibc::Height::new(ETHEREUM_CLIENT_REVISION_NUMBER, 1).unwrap(),
                    sync_committee: current_sync_committee.to_committee().clone(),
                    is_next: true,
                },
                consensus_update: update,
                execution_update: ExecutionUpdateInfo {
                    block_number: U64(2),
                    ..Default::default()
                },
                account_update: AccountUpdateInfo::default(),
                timestamp: Timestamp::from_nanoseconds(0).unwrap(),
            };
            let any = IBCAny::from(header.clone());
            let res = Header::<32>::try_from(any);
            assert!(res.is_err(), "header with zero timestamp should fail");
        }

        let (update, _) = gen_light_client_update_with_params::<32, _>(
            &ctx,
            base_signature_slot,
            base_attested_slot,
            base_finalized_epoch,
            dummy_execution_state_root,
            dummy_execution_block_number.into(),
            current_sync_committee,
            scm.get_committee(2),
            true,
            32,
        );
        let update = to_consensus_update_info(update);
        let header = Header {
            trusted_sync_committee: TrustedSyncCommittee {
                height: ibc::Height::new(ETHEREUM_CLIENT_REVISION_NUMBER, 1).unwrap(),
                sync_committee: current_sync_committee.to_committee().clone(),
                is_next: true,
            },
            consensus_update: update.clone(),
            execution_update: ExecutionUpdateInfo::default(),
            account_update: AccountUpdateInfo::default(),
            timestamp: Timestamp::from_nanoseconds(
                compute_timestamp_at_slot(&ctx, update.finalized_beacon_header().slot).0
                    * 1_000_000_000
                    + 1,
            )
            .unwrap(),
        };
        let res = header.validate(&ctx);
        assert!(
            res.is_err(),
            "header validation should fail for wrong timestamp"
        );
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
