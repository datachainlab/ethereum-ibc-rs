use crate::commitment::decode_eip1184_rlp_proof;
use crate::errors::Error;
use crate::internal_prelude::*;
use crate::misbehaviour::Misbehaviour;
use crate::update::{
    new_consensus_update, ConsensusUpdateInfo, ExecutionUpdateInfo, LightClientUpdate,
};
use bytes::Buf;
use ethereum_consensus::beacon::BeaconBlockHeader;
use ethereum_consensus::bls::{PublicKey, Signature};
use ethereum_consensus::sync_protocol::{SyncAggregate, SyncCommittee};
use ethereum_consensus::types::H256;
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::BeaconBlockHeader as ProtoBeaconBlockHeader;
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::Header as RawHeader;
use ethereum_light_client_verifier::updates::ConsensusUpdate;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::header::Header as Ics02Header;
use ibc::timestamp::Timestamp;
use ibc::Height;
use ibc_proto::google::protobuf::Any as IBCAny;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use ssz_rs::{Bitvector, Deserialize, Vector};

pub const ETHEREUM_HEADER_TYPE_URL: &str = "/ibc.lightclients.ethereum.v1.Header";

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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedSyncCommittee<const SYNC_COMMITTEE_SIZE: usize> {
    /// height(i.e. execution's block number) to trusted sync committee stored at
    pub height: Height,
    /// trusted sync committee
    pub sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    pub is_next: bool,
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
        fn timestamp_from_seconds(secs: u64) -> Timestamp {
            Timestamp::from_nanoseconds(secs * 1_000_000_000).unwrap()
        }

        let trusted_height = value.trusted_height.unwrap();
        let trusted_sync_committee = value.trusted_sync_committee.unwrap();
        let consensus_update = value.consensus_update.unwrap();
        let attested_header =
            proto_to_beacon_block_header(consensus_update.attested_header.as_ref().unwrap())?;
        let finalized_header =
            proto_to_beacon_block_header(consensus_update.finalized_header.as_ref().unwrap())?;
        let execution_update = value.execution_update.unwrap();
        let account_update = value.account_update.unwrap();

        let light_client_update = LightClientUpdate {
            attested_header,
            next_sync_committee: if consensus_update.next_sync_committee.is_none()
                || consensus_update
                    .next_sync_committee
                    .as_ref()
                    .unwrap()
                    .pubkeys
                    .len()
                    == 0
                || consensus_update.next_sync_committee_branch.len() == 0
            {
                None
            } else {
                Some((
                    SyncCommittee {
                        pubkeys: Vector::<PublicKey, SYNC_COMMITTEE_SIZE>::from_iter(
                            consensus_update
                                .next_sync_committee
                                .clone()
                                .unwrap()
                                .pubkeys
                                .into_iter()
                                .map(|pk| PublicKey::try_from(pk).unwrap()),
                        ),
                        aggregate_pubkey: PublicKey::try_from(
                            consensus_update
                                .next_sync_committee
                                .unwrap()
                                .aggregate_pubkey,
                        )?,
                    },
                    decode_branch(consensus_update.next_sync_committee_branch),
                ))
            },
            finalized_header: (
                finalized_header,
                decode_branch(consensus_update.finalized_header_branch),
            ),
            sync_aggregate: SyncAggregate {
                sync_committee_bits: Bitvector::<SYNC_COMMITTEE_SIZE>::deserialize(
                    consensus_update
                        .sync_aggregate
                        .clone()
                        .unwrap()
                        .sync_committee_bits
                        .as_slice(),
                )?,
                sync_committee_signature: Signature::try_from(
                    consensus_update
                        .sync_aggregate
                        .unwrap()
                        .sync_committee_signature,
                )?,
            },
            signature_slot: consensus_update.signature_slot.into(),
        };

        let consensus_update = new_consensus_update(
            light_client_update,
            H256::from_slice(&consensus_update.finalized_execution_root),
            consensus_update
                .finalized_execution_branch
                .into_iter()
                .map(|n| H256::from_slice(&n))
                .collect(),
        );
        Ok(Self {
            trusted_sync_committee: TrustedSyncCommittee {
                height: Height::new(
                    trusted_height.revision_number,
                    trusted_height.revision_height,
                )?,
                sync_committee: SyncCommittee {
                    pubkeys: Vector::<PublicKey, SYNC_COMMITTEE_SIZE>::from_iter(
                        trusted_sync_committee
                            .sync_committee
                            .as_ref()
                            .unwrap()
                            .pubkeys
                            .clone()
                            .into_iter()
                            .map(|pk| PublicKey::try_from(pk).unwrap()),
                    ),
                    aggregate_pubkey: PublicKey::try_from(
                        trusted_sync_committee
                            .sync_committee
                            .unwrap()
                            .aggregate_pubkey,
                    )?,
                },
                is_next: trusted_sync_committee.is_next,
            },
            consensus_update,
            execution_update: ExecutionUpdateInfo {
                state_root: H256::from_slice(&execution_update.state_root),
                state_root_branch: execution_update
                    .state_root_branch
                    .into_iter()
                    .map(|n| H256::from_slice(&n))
                    .collect(),
                block_number: execution_update.block_number.into(),
                block_number_branch: execution_update
                    .block_number_branch
                    .into_iter()
                    .map(|n| H256::from_slice(&n))
                    .collect(),
            },
            account_update: AccountUpdateInfo {
                account_proof: decode_eip1184_rlp_proof(account_update.account_proof)?,
                account_storage_root: H256::from_slice(&account_update.account_storage_root),
            },
            timestamp: timestamp_from_seconds(value.timestamp),
        })
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<Header<SYNC_COMMITTEE_SIZE>> for RawHeader {
    fn from(value: Header<SYNC_COMMITTEE_SIZE>) -> Self {
        use ethereum_ibc_proto::ibc::core::client::v1::Height as ProtoHeight;
        use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::{
            AccountUpdate as ProtoAccountUpdate, ExecutionUpdate as ProtoExecutionUpdate,
            LightClientUpdate as ProtoLightClientUpdate, SyncAggregate as ProtoSyncAggregate,
            SyncCommittee as ProtoSyncCommittee, TrustedSyncCommittee as ProtoTrustedSyncCommittee,
        };

        let consensus_update = value.consensus_update;
        let finalized_beacon_header = consensus_update.finalized_beacon_header().clone();
        let finalized_beacon_header_branch =
            consensus_update.finalized_beacon_header_branch().clone();
        let sync_aggregate = consensus_update.light_client_update.sync_aggregate.clone();
        let signature_slot = consensus_update.signature_slot();
        let light_client_update = consensus_update.light_client_update;
        let execution_update = value.execution_update;
        let account_update = value.account_update;

        Self {
            trusted_height: Some(ProtoHeight {
                revision_number: value.trusted_sync_committee.height.revision_number(),
                revision_height: value.trusted_sync_committee.height.revision_height(),
            }),
            trusted_sync_committee: Some(ProtoTrustedSyncCommittee {
                sync_committee: Some(ProtoSyncCommittee {
                    pubkeys: value
                        .trusted_sync_committee
                        .sync_committee
                        .pubkeys
                        .iter()
                        .map(|pk| pk.to_vec())
                        .collect(),
                    aggregate_pubkey: value
                        .trusted_sync_committee
                        .sync_committee
                        .aggregate_pubkey
                        .to_vec(),
                }),
                is_next: value.trusted_sync_committee.is_next,
            }),
            consensus_update: Some(ProtoLightClientUpdate {
                attested_header: Some(ProtoBeaconBlockHeader {
                    slot: light_client_update.attested_header.slot.into(),
                    proposer_index: light_client_update.attested_header.proposer_index.into(),
                    parent_root: light_client_update
                        .attested_header
                        .parent_root
                        .as_bytes()
                        .to_vec(),
                    state_root: light_client_update
                        .attested_header
                        .state_root
                        .as_bytes()
                        .to_vec(),
                    body_root: light_client_update
                        .attested_header
                        .body_root
                        .as_bytes()
                        .to_vec(),
                }),
                next_sync_committee: light_client_update.next_sync_committee.clone().map(|c| {
                    ProtoSyncCommittee {
                        pubkeys: c.0.pubkeys.iter().map(|pk| pk.to_vec()).collect(),
                        aggregate_pubkey: c.0.aggregate_pubkey.to_vec(),
                    }
                }),
                next_sync_committee_branch: light_client_update
                    .next_sync_committee
                    .map_or(Vec::new(), |(_, branch)| {
                        branch.into_iter().map(|n| n.as_bytes().to_vec()).collect()
                    }),
                finalized_header: Some(ProtoBeaconBlockHeader {
                    slot: light_client_update.finalized_header.0.slot.into(),
                    proposer_index: finalized_beacon_header.proposer_index.into(),
                    parent_root: finalized_beacon_header.parent_root.as_bytes().to_vec(),
                    state_root: finalized_beacon_header.state_root.as_bytes().to_vec(),
                    body_root: finalized_beacon_header.body_root.as_bytes().to_vec(),
                }),
                finalized_header_branch: finalized_beacon_header_branch
                    .into_iter()
                    .map(|n| n.as_bytes().to_vec())
                    .collect(),
                finalized_execution_root: consensus_update
                    .finalized_execution_root
                    .as_bytes()
                    .into(),
                finalized_execution_branch: consensus_update
                    .finalized_execution_branch
                    .into_iter()
                    .map(|n| n.as_bytes().to_vec())
                    .collect(),
                sync_aggregate: Some(ProtoSyncAggregate {
                    sync_committee_bits: sync_aggregate
                        .sync_committee_bits
                        .iter()
                        .map(|b| if b == true { 1 } else { 0 })
                        .collect(),
                    sync_committee_signature: sync_aggregate.sync_committee_signature.0.to_vec(),
                }),
                signature_slot: signature_slot.into(),
            }),
            execution_update: Some(ProtoExecutionUpdate {
                state_root: execution_update.state_root.as_bytes().into(),
                state_root_branch: execution_update
                    .state_root_branch
                    .into_iter()
                    .map(|n| n.as_bytes().to_vec())
                    .collect(),
                block_number: execution_update.block_number.into(),
                block_number_branch: execution_update
                    .block_number_branch
                    .into_iter()
                    .map(|n| n.as_bytes().to_vec())
                    .collect(),
            }),
            account_update: Some(ProtoAccountUpdate {
                account_proof: encode_account_proof(account_update.account_proof),
                account_storage_root: account_update.account_storage_root.as_bytes().to_vec(),
            }),
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

pub fn decode_header<const SYNC_COMMITTEE_SIZE: usize, B: Buf>(
    buf: B,
) -> Result<Header<SYNC_COMMITTEE_SIZE>, Error> {
    RawHeader::decode(buf).map_err(Error::Decode)?.try_into()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountUpdateInfo {
    pub account_proof: Vec<Vec<u8>>,
    pub account_storage_root: H256,
}

fn encode_account_proof(bz: Vec<Vec<u8>>) -> Vec<u8> {
    let proof: Vec<Vec<u8>> = bz.into_iter().map(|b| b.to_vec()).collect();
    let mut stream = rlp::RlpStream::new();
    stream.begin_list(proof.len());
    for p in proof.iter() {
        stream.append_raw(p, 1);
    }
    stream.out().freeze().into()
}

fn decode_branch<const N: usize>(bz: Vec<Vec<u8>>) -> [H256; N]
where
    [H256; N]: Default,
{
    let mut array: [H256; N] = Default::default();
    let v: Vec<H256> = bz.into_iter().map(|b| H256::from_slice(&b)).collect();
    array.clone_from_slice(v.as_slice());
    array
}

fn proto_to_beacon_block_header(
    header: &ProtoBeaconBlockHeader,
) -> Result<BeaconBlockHeader, Error> {
    Ok(BeaconBlockHeader {
        slot: header.slot.into(),
        proposer_index: header.proposer_index.into(),
        parent_root: H256::from_slice(&header.parent_root),
        state_root: H256::from_slice(&header.state_root),
        body_root: H256::from_slice(&header.body_root),
    })
}
