use crate::commitment::{calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof};
use crate::consensus_state::{ConsensusState, TrustedConsensusState};
use crate::errors::Error;
use crate::header::Header;
use crate::misbehaviour::Misbehaviour;
use crate::update::apply_updates;
use crate::{eth_client_type, internal_prelude::*};
use core::time::Duration;
use ethereum_consensus::beacon::{Epoch, Root, Slot, Version};
use ethereum_consensus::context::ChainContext;
use ethereum_consensus::fork::{ForkParameter, ForkParameters};
use ethereum_consensus::preset;
use ethereum_consensus::types::{Address, H256, U64};
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::{ClientState as RawClientState, Fork};
use ethereum_light_client_verifier::consensus::{
    CurrentNextSyncProtocolVerifier, SyncProtocolVerifier,
};
use ethereum_light_client_verifier::context::{
    ConsensusVerificationContext, Fraction, LightClientContext,
};
use ethereum_light_client_verifier::execution::ExecutionVerifier;
use ibc::core::ics02_client::client_state::{ClientState as Ics2ClientState, UpdatedState};
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::consensus_state::ConsensusState as Ics02ConsensusState;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics24_host::identifier::{ChainId, ClientId};
use ibc::core::ics24_host::path::ClientConsensusStatePath;
use ibc::core::ics24_host::Path;
use ibc::core::{ContextError, ValidationContext};
use ibc::Height;
use ibc_proto::google::protobuf::Any;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use serde::{Deserialize, Serialize};

pub const ETHEREUM_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.ethereum.v1.ClientState";

pub type MainnetClientState = ClientState<{ preset::mainnet::PRESET.SYNC_COMMITTEE_SIZE }>;
pub type MinimalClientState = ClientState<{ preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState<const SYNC_COMMITTEE_SIZE: usize> {
    /// Chain parameters
    pub genesis_validators_root: Root,
    pub min_sync_committee_participants: U64,
    pub genesis_time: U64,
    pub fork_parameters: ForkParameters,
    pub seconds_per_slot: U64,
    pub slots_per_epoch: Slot,
    pub epochs_per_sync_committee_period: Epoch,

    /// IBC Solidity parameters
    pub ibc_address: Address,
    pub ibc_commitments_slot: H256,

    /// Light Client parameters
    pub trust_level: Fraction,
    pub trusting_period: Duration,

    /// State
    pub latest_slot: Slot,
    pub latest_execution_block_number: U64,
    pub frozen_height: Option<Height>,

    /// Verifier
    #[serde(skip)]
    pub consensus_verifier:
        CurrentNextSyncProtocolVerifier<TrustedConsensusState<SYNC_COMMITTEE_SIZE>>,
    #[serde(skip)]
    pub execution_verifier: ExecutionVerifier,
}

impl<const SYNC_COMMITTEE_SIZE: usize> ClientState<SYNC_COMMITTEE_SIZE> {
    pub fn with_frozen_height(self, h: Height) -> Self {
        Self {
            frozen_height: Some(h),
            ..self
        }
    }

    pub fn build_context(
        &self,
        vctx: &dyn ValidationContext,
    ) -> impl ChainContext + ConsensusVerificationContext {
        let current_timestamp = U64::from(
            vctx.host_timestamp()
                .unwrap()
                .into_tm_time()
                .unwrap()
                .unix_timestamp() as u64,
        );
        let current_slot = (current_timestamp - self.genesis_time) / self.seconds_per_slot
            + self.fork_parameters.genesis_slot();
        LightClientContext::new(
            self.fork_parameters.clone(),
            self.seconds_per_slot,
            self.slots_per_epoch,
            self.epochs_per_sync_committee_period,
            self.genesis_time,
            self.genesis_validators_root.clone(),
            self.min_sync_committee_participants.0 as usize,
            self.trust_level.clone(),
            move || current_slot,
        )
    }

    pub fn verify_membership(
        &self,
        _counterparty_prefix: &ibc::core::ics23_commitment::commitment::CommitmentPrefix,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        path: impl Into<Path>,
        value: Vec<u8>,
    ) -> Result<(), ClientError> {
        let proof = decode_eip1184_rlp_proof(proof.clone().try_into().map_err(|e| {
            ClientError::Other {
                description: format!("{}", e),
            }
        })?)?;
        let path = path.into();
        let key = calculate_ibc_commitment_storage_key(&self.ibc_commitments_slot, path.clone());
        self.execution_verifier
            .verify_membership(
                H256::from_slice(root.as_bytes()),
                key.as_bytes(),
                rlp::encode(&value).as_ref(),
                proof.clone(),
            )
            .map_err(|e| ClientError::ClientSpecific {
                description: format!(
                    "failed to verify membership: path={} root={:?} value={:?} proof={:?} error={}",
                    path,
                    root,
                    value,
                    proof,
                    e.to_string()
                ),
            })?;
        Ok(())
    }

    pub fn verify_non_membership(
        &self,
        _counterparty_prefix: &ibc::core::ics23_commitment::commitment::CommitmentPrefix,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        path: impl Into<Path>,
    ) -> Result<(), ibc::core::ics02_client::error::ClientError> {
        let proof = decode_eip1184_rlp_proof(proof.clone().try_into().map_err(|e| {
            ClientError::Other {
                description: format!("{}", e),
            }
        })?)?;
        let path = path.into();
        let key = calculate_ibc_commitment_storage_key(&self.ibc_commitments_slot, path.clone());
        self.execution_verifier
            .verify_non_membership(
                H256::from_slice(root.as_bytes()),
                key.as_bytes(),
                proof.clone(),
            )
            .map_err(|e| ClientError::ClientSpecific {
                description: format!(
                    "failed to verify non-membership: path={} root={:?} proof={:?} error={}",
                    path,
                    root,
                    proof,
                    e.to_string()
                ),
            })?;
        Ok(())
    }

    /// Verify that the client is at a sufficient height and unfrozen at the given height
    pub fn verify_height(&self, height: Height) -> Result<(), Error> {
        if self.latest_height() < height {
            return Err(Error::InsufficientHeight {
                latest_height: self.latest_height(),
                target_height: height,
            });
        }

        // TODO implement this
        // match self.frozen_height {
        //     Some(frozen_height) if frozen_height <= height => Err(Error::ClientFrozen {
        //         frozen_height,
        //         target_height: height,
        //     }),
        //     _ => Ok(()),
        // }
        Ok(())
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Ics2ClientState for ClientState<SYNC_COMMITTEE_SIZE> {
    fn chain_id(&self) -> ChainId {
        todo!()
    }

    fn client_type(&self) -> ClientType {
        eth_client_type()
    }

    fn latest_height(&self) -> Height {
        Height::new(0, self.latest_execution_block_number.into()).unwrap()
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height.clone()
    }

    #[allow(unused_variables)]
    fn expired(&self, elapsed: Duration) -> bool {
        todo!()
    }

    fn zero_custom_fields(&mut self) {
        todo!()
    }

    fn initialise(
        &self,
        consensus_state: Any,
    ) -> Result<Box<dyn Ics02ConsensusState>, ClientError> {
        ConsensusState::try_from(consensus_state).map(ConsensusState::into_box)
    }

    fn check_header_and_update_state(
        &self,
        ctx: &dyn ValidationContext,
        client_id: ClientId,
        header: Any,
    ) -> Result<UpdatedState, ClientError> {
        let header = Header::<SYNC_COMMITTEE_SIZE>::try_from(header)?;
        let trusted_sync_committee = header.trusted_sync_committee;
        let consensus_state = match maybe_consensus_state(
            ctx,
            &ClientConsensusStatePath::new(&client_id, &trusted_sync_committee.height),
        )? {
            Some(cs) => cs,
            None => {
                return Err(ClientError::ConsensusStateNotFound {
                    client_id,
                    height: trusted_sync_committee.height,
                })
            }
        };

        let trusted_consensus_state = TrustedConsensusState::new(
            consensus_state,
            trusted_sync_committee.sync_committee,
            trusted_sync_committee.is_next,
        )?;

        let consensus_update = header.consensus_update;
        let execution_update = header.execution_update;
        let account_update = header.account_update;
        let timestamp = header.timestamp;

        let cc = self.build_context(ctx);
        self.consensus_verifier
            .validate_updates(
                &cc,
                &trusted_consensus_state,
                &consensus_update,
                &execution_update,
            )
            .map_err(Error::VerificationError)?;

        let (new_client_state, new_consensus_state) = apply_updates(
            &cc,
            self,
            &trusted_consensus_state,
            consensus_update,
            execution_update,
            account_update,
            timestamp,
        )?;

        Ok(UpdatedState {
            client_state: new_client_state.into_box(),
            consensus_state: new_consensus_state.into_box(),
        })
    }

    fn check_misbehaviour_and_update_state(
        &self,
        ctx: &dyn ValidationContext,
        client_id: ClientId,
        misbehaviour: Any,
    ) -> Result<alloc::boxed::Box<dyn Ics2ClientState>, ibc::core::ContextError> {
        let misbehaviour = Misbehaviour::<SYNC_COMMITTEE_SIZE>::try_from(misbehaviour)?;
        let consensus_state = match maybe_consensus_state(
            ctx,
            &ClientConsensusStatePath::new(&client_id, &misbehaviour.trusted_sync_committee.height),
        )? {
            Some(cs) => cs,
            None => {
                return Err(ClientError::ConsensusStateNotFound {
                    client_id,
                    height: misbehaviour.trusted_sync_committee.height,
                }
                .into())
            }
        };

        let cc = self.build_context(ctx);
        let trusted_consensus_state = TrustedConsensusState::new(
            consensus_state,
            misbehaviour.trusted_sync_committee.sync_committee,
            misbehaviour.trusted_sync_committee.is_next,
        )?;

        self.consensus_verifier
            .validate_misbehaviour(&cc, &trusted_consensus_state, misbehaviour.data)
            .map_err(Error::VerificationError)?;

        // found misbehaviour
        Ok(self
            .clone()
            .with_frozen_height(misbehaviour.trusted_sync_committee.height)
            .into_box())
    }

    #[allow(unused_variables)]
    fn verify_upgrade_client(
        &self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
        proof_upgrade_client: ibc_proto::ibc::core::commitment::v1::MerkleProof,
        proof_upgrade_consensus_state: ibc_proto::ibc::core::commitment::v1::MerkleProof,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
    ) -> Result<(), ClientError> {
        todo!()
    }

    #[allow(unused_variables)]
    fn update_state_with_upgrade_client(
        &self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
    ) -> Result<UpdatedState, ClientError> {
        todo!()
    }

    fn verify_client_consensus_state(
        &self,
        proof_height: ibc::Height,
        counterparty_prefix: &ibc::core::ics23_commitment::commitment::CommitmentPrefix,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        client_cons_state_path: &ibc::core::ics24_host::path::ClientConsensusStatePath,
        expected_consensus_state: &dyn ibc::core::ics02_client::consensus_state::ConsensusState,
    ) -> Result<(), ClientError> {
        let client_state = downcast_eth_client_state::<SYNC_COMMITTEE_SIZE>(self)?;
        client_state.verify_height(proof_height)?;

        let value = expected_consensus_state
            .encode_vec()
            .map_err(ClientError::InvalidAnyConsensusState)?;
        self.verify_membership(
            counterparty_prefix,
            proof,
            root,
            client_cons_state_path.clone(),
            value,
        )
    }

    fn verify_connection_state(
        &self,
        proof_height: ibc::Height,
        counterparty_prefix: &ibc::core::ics23_commitment::commitment::CommitmentPrefix,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        counterparty_conn_path: &ibc::core::ics24_host::path::ConnectionPath,
        expected_counterparty_connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
    ) -> Result<(), ClientError> {
        let client_state = downcast_eth_client_state::<SYNC_COMMITTEE_SIZE>(self)?;
        client_state.verify_height(proof_height)?;

        let value = expected_counterparty_connection_end
            .encode_vec()
            .map_err(ClientError::InvalidConnectionEnd)?;
        self.verify_membership(
            counterparty_prefix,
            proof,
            root,
            counterparty_conn_path.clone(),
            value,
        )
    }

    fn verify_channel_state(
        &self,
        proof_height: ibc::Height,
        counterparty_prefix: &ibc::core::ics23_commitment::commitment::CommitmentPrefix,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        counterparty_chan_end_path: &ibc::core::ics24_host::path::ChannelEndPath,
        expected_counterparty_channel_end: &ibc::core::ics04_channel::channel::ChannelEnd,
    ) -> Result<(), ClientError> {
        let client_state = downcast_eth_client_state::<SYNC_COMMITTEE_SIZE>(self)?;
        client_state.verify_height(proof_height)?;

        let value = expected_counterparty_channel_end
            .encode_vec()
            .map_err(ClientError::InvalidChannelEnd)?;

        self.verify_membership(
            counterparty_prefix,
            proof,
            root,
            counterparty_chan_end_path.clone(),
            value,
        )
    }

    fn verify_client_full_state(
        &self,
        proof_height: ibc::Height,
        counterparty_prefix: &ibc::core::ics23_commitment::commitment::CommitmentPrefix,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        client_state_path: &ibc::core::ics24_host::path::ClientStatePath,
        expected_client_state: Any,
    ) -> Result<(), ClientError> {
        let client_state = downcast_eth_client_state::<SYNC_COMMITTEE_SIZE>(self)?;
        client_state.verify_height(proof_height)?;

        let value = expected_client_state.encode_to_vec();

        self.verify_membership(
            counterparty_prefix,
            proof,
            root,
            client_state_path.clone(),
            value,
        )
    }

    fn verify_packet_data(
        &self,
        _ctx: &dyn ibc::core::ValidationContext,
        height: ibc::Height,
        connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        commitment_path: &ibc::core::ics24_host::path::CommitmentPath,
        commitment: ibc::core::ics04_channel::commitment::PacketCommitment,
    ) -> Result<(), ClientError> {
        let client_state = downcast_eth_client_state::<SYNC_COMMITTEE_SIZE>(self)?;
        client_state.verify_height(height)?;

        self.verify_membership(
            connection_end.counterparty().prefix(),
            proof,
            root,
            commitment_path.clone(),
            commitment.into_vec(),
        )
    }

    fn verify_packet_acknowledgement(
        &self,
        _ctx: &dyn ibc::core::ValidationContext,
        height: ibc::Height,
        connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        ack_path: &ibc::core::ics24_host::path::AckPath,
        ack: ibc::core::ics04_channel::commitment::AcknowledgementCommitment,
    ) -> Result<(), ClientError> {
        let client_state = downcast_eth_client_state::<SYNC_COMMITTEE_SIZE>(self)?;
        client_state.verify_height(height)?;

        self.verify_membership(
            connection_end.counterparty().prefix(),
            proof,
            root,
            ack_path.clone(),
            ack.into_vec(),
        )
    }

    fn verify_next_sequence_recv(
        &self,
        _ctx: &dyn ibc::core::ValidationContext,
        height: ibc::Height,
        connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        seq_recv_path: &ibc::core::ics24_host::path::SeqRecvPath,
        sequence: ibc::core::ics04_channel::packet::Sequence,
    ) -> Result<(), ClientError> {
        let client_state = downcast_eth_client_state::<SYNC_COMMITTEE_SIZE>(self)?;
        client_state.verify_height(height)?;

        let mut seq_bytes = Vec::new();
        u64::from(sequence)
            .encode(&mut seq_bytes)
            .expect("buffer size too small");

        self.verify_membership(
            connection_end.counterparty().prefix(),
            proof,
            root,
            seq_recv_path.clone(),
            seq_bytes,
        )
    }

    fn verify_packet_receipt_absence(
        &self,
        _ctx: &dyn ibc::core::ValidationContext,
        height: ibc::Height,
        connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        receipt_path: &ibc::core::ics24_host::path::ReceiptPath,
    ) -> Result<(), ClientError> {
        let client_state = downcast_eth_client_state::<SYNC_COMMITTEE_SIZE>(self)?;
        client_state.verify_height(height)?;

        self.verify_non_membership(
            connection_end.counterparty().prefix(),
            proof,
            root,
            receipt_path.clone(),
        )
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<RawClientState>
    for ClientState<SYNC_COMMITTEE_SIZE>
{
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawClientState>
    for ClientState<SYNC_COMMITTEE_SIZE>
{
    type Error = Error;

    fn try_from(value: RawClientState) -> Result<Self, Self::Error> {
        fn bytes_to_version(bz: Vec<u8>) -> Version {
            assert_eq!(bz.len(), 4);
            let mut version = Version::default();
            version.0.copy_from_slice(&bz);
            version
        }

        let raw_fork_parameters = value.fork_parameters.unwrap();
        let fork_parameters = ForkParameters::new(
            bytes_to_version(raw_fork_parameters.genesis_fork_version),
            raw_fork_parameters
                .forks
                .into_iter()
                .map(|f| ForkParameter::new(bytes_to_version(f.version), f.epoch.into()))
                .collect(),
        );
        fork_parameters.validate()?;
        let trust_level = value.trust_level.unwrap();
        Ok(Self {
            genesis_validators_root: H256::from_slice(&value.genesis_validators_root),
            min_sync_committee_participants: value.min_sync_committee_participants.into(),
            genesis_time: value.genesis_time.into(),
            fork_parameters,
            seconds_per_slot: value.seconds_per_slot.into(),
            slots_per_epoch: value.slots_per_epoch.into(),
            epochs_per_sync_committee_period: value.epochs_per_sync_committee_period.into(),
            ibc_address: value.ibc_address.as_slice().try_into()?,
            ibc_commitments_slot: H256::from_slice(&value.ibc_commitments_slot),
            trust_level: Fraction::new(trust_level.numerator, trust_level.denominator),
            trusting_period: Duration::from_secs(value.trusting_period),
            latest_slot: value.latest_slot.into(),
            latest_execution_block_number: value.latest_execution_block_number.into(),
            frozen_height: value
                .frozen_height
                .map(|h| Height::new(h.revision_number, h.revision_height).unwrap()),
            consensus_verifier: Default::default(),
            execution_verifier: Default::default(),
        })
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<ClientState<SYNC_COMMITTEE_SIZE>> for RawClientState {
    fn from(value: ClientState<SYNC_COMMITTEE_SIZE>) -> Self {
        use ethereum_ibc_proto::ibc::core::client::v1::Height as ProtoHeight;
        use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::{
            ForkParameters as ProtoForkParameters, Fraction as ProtoFraction,
        };

        fn make_fork(version: Version, epoch: U64) -> Fork {
            Fork {
                version: version_to_bytes(version),
                epoch: epoch.into(),
            }
        }

        fn version_to_bytes(version: Version) -> Vec<u8> {
            version.0.to_vec()
        }

        let fork_parameters = value.fork_parameters;

        Self {
            genesis_validators_root: value.genesis_validators_root.as_bytes().to_vec(),
            min_sync_committee_participants: value.min_sync_committee_participants.into(),
            genesis_time: value.genesis_time.into(),
            fork_parameters: Some(ProtoForkParameters {
                genesis_fork_version: version_to_bytes(fork_parameters.genesis_version),
                forks: fork_parameters
                    .forks
                    .into_iter()
                    .map(|f| make_fork(f.version, f.epoch))
                    .collect(),
            }),
            seconds_per_slot: value.seconds_per_slot.into(),
            slots_per_epoch: value.slots_per_epoch.into(),
            epochs_per_sync_committee_period: value.epochs_per_sync_committee_period.into(),
            ibc_address: value.ibc_address.0.to_vec(),
            ibc_commitments_slot: value.ibc_commitments_slot.as_bytes().to_vec(),
            trust_level: Some(ProtoFraction {
                numerator: value.trust_level.numerator,
                denominator: value.trust_level.denominator,
            }),
            trusting_period: value.trusting_period.as_secs(),
            latest_slot: value.latest_slot.into(),
            latest_execution_block_number: value.latest_execution_block_number.into(),
            frozen_height: value.frozen_height.map(|h| ProtoHeight {
                revision_number: h.revision_number(),
                revision_height: h.revision_height(),
            }),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Protobuf<Any> for ClientState<SYNC_COMMITTEE_SIZE> {}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<Any> for ClientState<SYNC_COMMITTEE_SIZE> {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_client_state<const SYNC_COMMITTEE_SIZE: usize, B: Buf>(
            buf: B,
        ) -> Result<ClientState<SYNC_COMMITTEE_SIZE>, Error> {
            RawClientState::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            ETHEREUM_CLIENT_STATE_TYPE_URL => {
                decode_client_state::<SYNC_COMMITTEE_SIZE, &[u8]>(raw.value.deref())
                    .map_err(Into::into)
            }
            _ => Err(ClientError::UnknownClientStateType {
                client_state_type: raw.type_url,
            }),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> From<ClientState<SYNC_COMMITTEE_SIZE>> for Any {
    fn from(value: ClientState<SYNC_COMMITTEE_SIZE>) -> Self {
        Self {
            type_url: ETHEREUM_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawClientState>::encode_vec(&value)
                .expect("encoding to `Any` from `ClientState`"),
        }
    }
}

fn downcast_eth_client_state<const SYNC_COMMITTEE_SIZE: usize>(
    cs: &dyn Ics2ClientState,
) -> Result<&ClientState<SYNC_COMMITTEE_SIZE>, ClientError> {
    cs.as_any()
        .downcast_ref::<ClientState<SYNC_COMMITTEE_SIZE>>()
        .ok_or_else(|| ClientError::ClientArgsTypeMismatch {
            client_type: eth_client_type(),
        })
}

fn downcast_eth_consensus_state(
    cs: &dyn Ics02ConsensusState,
) -> Result<ConsensusState, ClientError> {
    cs.as_any()
        .downcast_ref::<ConsensusState>()
        .ok_or_else(|| ClientError::ClientArgsTypeMismatch {
            client_type: eth_client_type(),
        })
        .map(Clone::clone)
}

fn maybe_consensus_state(
    ctx: &dyn ValidationContext,
    client_cons_state_path: &ClientConsensusStatePath,
) -> Result<Option<ConsensusState>, ClientError> {
    match ctx.consensus_state(client_cons_state_path) {
        Ok(cs) => Ok(Some(downcast_eth_consensus_state(cs.as_ref())?)),
        Err(e) => match e {
            ContextError::ClientError(ClientError::ConsensusStateNotFound {
                client_id: _,
                height: _,
            }) => Ok(None),
            ContextError::ClientError(e) => Err(e),
            _ => Err(ClientError::Other {
                description: e.to_string(),
            }),
        },
    }
}
