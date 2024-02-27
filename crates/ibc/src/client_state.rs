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
use ibc::timestamp::Timestamp;
use ibc::Height;
use ibc_proto::google::protobuf::Any;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use serde::{Deserialize, Serialize};

pub const ETHEREUM_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.ethereum.v1.ClientState";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize>
{
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
    pub max_clock_drift: Duration,

    /// State
    pub latest_slot: Slot,
    pub latest_execution_block_number: U64,
    pub frozen_height: Option<Height>,

    /// Verifier
    #[serde(skip)]
    pub consensus_verifier: CurrentNextSyncProtocolVerifier<
        SYNC_COMMITTEE_SIZE,
        EXECUTION_PAYLOAD_TREE_DEPTH,
        TrustedConsensusState<SYNC_COMMITTEE_SIZE>,
    >,
    #[serde(skip)]
    pub execution_verifier: ExecutionVerifier,
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize>
    ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>
{
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
            self.genesis_validators_root,
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
        let proof = decode_eip1184_rlp_proof(proof.clone().into())?;
        let path = path.into();
        let key = calculate_ibc_commitment_storage_key(&self.ibc_commitments_slot, path.clone());
        self.execution_verifier
            .verify_membership(
                H256::from_slice(root.as_bytes()),
                key.as_bytes(),
                rlp::encode(&trim_left_zero(&value)).as_ref(),
                proof.clone(),
            )
            .map_err(|e| ClientError::ClientSpecific {
                description: format!(
                    "failed to verify membership: path={} root={:?} value={:?} proof={:?} error={}",
                    path, root, value, proof, e
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
        let proof = decode_eip1184_rlp_proof(proof.clone().into())?;
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
                    path, root, proof, e
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
        match self.frozen_height {
            Some(frozen_height) if frozen_height <= height => Err(Error::ClientFrozen {
                frozen_height,
                target_height: height,
            }),
            _ => Ok(()),
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.genesis_validators_root == Root::default() {
            Err(Error::UninitializedClientStateField(
                "genesis_validators_root",
            ))
        } else if self.min_sync_committee_participants == U64::default() {
            Err(Error::UninitializedClientStateField(
                "min_sync_committee_participants",
            ))
        } else if self.genesis_time == U64::default() {
            Err(Error::UninitializedClientStateField("genesis_time"))
        } else if self.fork_parameters == ForkParameters::default() {
            Err(Error::UninitializedClientStateField("fork_parameters"))
        } else if self.seconds_per_slot == U64::default() {
            Err(Error::UninitializedClientStateField("seconds_per_slot"))
        } else if self.slots_per_epoch == Slot::default() {
            Err(Error::UninitializedClientStateField("slots_per_epoch"))
        } else if self.epochs_per_sync_committee_period == U64::default() {
            Err(Error::UninitializedClientStateField(
                "epochs_per_sync_committee_period",
            ))
        } else if self.ibc_address == Address::default() {
            Err(Error::UninitializedClientStateField("ibc_address"))
        } else if self.trust_level == Fraction::default() {
            Err(Error::UninitializedClientStateField("trust_level"))
        } else if self.trusting_period == Duration::default() {
            Err(Error::UninitializedClientStateField("trusting_period"))
        } else if self.latest_slot == Slot::default() {
            Err(Error::UninitializedClientStateField("latest_slot"))
        } else if self.latest_execution_block_number == U64::default() {
            Err(Error::UninitializedClientStateField(
                "latest_execution_block_number",
            ))
        } else {
            self.fork_parameters.validate()?;
            Ok(())
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize> Ics2ClientState
    for ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>
{
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
        self.frozen_height
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
        self.validate()?;
        let consensus_state = ConsensusState::try_from(consensus_state)?;
        consensus_state.validate()?;
        Ok(ConsensusState::into_box(consensus_state))
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

        // check if the current timestamp is within the trusting period
        validate_within_trusting_period(
            ctx.host_timestamp()
                .map_err(|e| ClientError::ClientSpecific {
                    description: e.to_string(),
                })?,
            self.trusting_period,
            self.max_clock_drift,
            timestamp,
            trusted_consensus_state.state.timestamp,
        )?;

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
        let client_state =
            downcast_eth_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>(self)?;
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
        let client_state =
            downcast_eth_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>(self)?;
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
        let client_state =
            downcast_eth_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>(self)?;
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
        let client_state =
            downcast_eth_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>(self)?;
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
        let client_state =
            downcast_eth_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>(self)?;
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
        let client_state =
            downcast_eth_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>(self)?;
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
        let client_state =
            downcast_eth_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>(self)?;
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
        let client_state =
            downcast_eth_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>(self)?;
        client_state.verify_height(height)?;

        self.verify_non_membership(
            connection_end.counterparty().prefix(),
            proof,
            root,
            receipt_path.clone(),
        )
    }
}

fn validate_within_trusting_period(
    current_timestamp: Timestamp,
    trusting_period: Duration,
    clock_drift: Duration,
    untrusted_header_timestamp: Timestamp,
    trusted_consensus_state_timestamp: Timestamp,
) -> Result<(), Error> {
    let trusting_period_end = (trusted_consensus_state_timestamp + trusting_period)?;
    let drifted_current_timestamp = (current_timestamp + clock_drift)?;

    if !trusting_period_end.after(&current_timestamp) {
        return Err(Error::OutOfTrustingPeriod {
            current_timestamp,
            trusting_period_end,
        });
    }
    if !drifted_current_timestamp.after(&untrusted_header_timestamp) {
        return Err(Error::HeaderFromFuture {
            current_timestamp,
            clock_drift,
            header_timestamp: untrusted_header_timestamp,
        });
    }
    Ok(())
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize>
    Protobuf<RawClientState> for ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>
{
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize>
    TryFrom<RawClientState> for ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>
{
    type Error = Error;

    fn try_from(value: RawClientState) -> Result<Self, Self::Error> {
        fn bytes_to_version(bz: Vec<u8>) -> Version {
            assert_eq!(bz.len(), 4);
            let mut version = Version::default();
            version.0.copy_from_slice(&bz);
            version
        }

        let raw_fork_parameters = value
            .fork_parameters
            .ok_or(Error::proto_missing("fork_parameters"))?;
        let fork_parameters = ForkParameters::new(
            bytes_to_version(raw_fork_parameters.genesis_fork_version),
            raw_fork_parameters
                .forks
                .into_iter()
                .map(|f| ForkParameter::new(bytes_to_version(f.version), f.epoch.into()))
                .collect(),
        );
        let trust_level = value
            .trust_level
            .ok_or(Error::proto_missing("trust_level"))?;
        let frozen_height = if let Some(h) = value.frozen_height {
            Some(Height::new(h.revision_number, h.revision_height)?)
        } else {
            None
        };
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
            trusting_period: value
                .trusting_period
                .ok_or(Error::MissingTrustingPeriod)?
                .try_into()
                .map_err(|_| Error::MissingTrustingPeriod)?,
            max_clock_drift: value
                .max_clock_drift
                .ok_or(Error::NegativeMaxClockDrift)?
                .try_into()
                .map_err(|_| Error::NegativeMaxClockDrift)?,
            latest_slot: value.latest_slot.into(),
            latest_execution_block_number: value.latest_execution_block_number.into(),
            frozen_height,
            consensus_verifier: Default::default(),
            execution_verifier: Default::default(),
        })
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize>
    From<ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>> for RawClientState
{
    fn from(value: ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>) -> Self {
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
            trusting_period: Some(value.trusting_period.into()),
            max_clock_drift: Some(value.max_clock_drift.into()),
            latest_slot: value.latest_slot.into(),
            latest_execution_block_number: value.latest_execution_block_number.into(),
            frozen_height: value.frozen_height.map(|h| ProtoHeight {
                revision_number: h.revision_number(),
                revision_height: h.revision_height(),
            }),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize> Protobuf<Any>
    for ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>
{
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize> TryFrom<Any>
    for ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>
{
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_client_state<
            const SYNC_COMMITTEE_SIZE: usize,
            const EXECUTION_PAYLOAD_TREE_DEPTH: usize,
            B: Buf,
        >(
            buf: B,
        ) -> Result<ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>, Error> {
            RawClientState::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            ETHEREUM_CLIENT_STATE_TYPE_URL => {
                decode_client_state::<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH, &[u8]>(
                    raw.value.deref(),
                )
                .map_err(Into::into)
            }
            _ => Err(ClientError::UnknownClientStateType {
                client_state_type: raw.type_url,
            }),
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize, const EXECUTION_PAYLOAD_TREE_DEPTH: usize>
    From<ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>> for Any
{
    fn from(value: ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>) -> Self {
        Self {
            type_url: ETHEREUM_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawClientState>::encode_vec(&value)
                .expect("encoding to `Any` from `ClientState`"),
        }
    }
}

fn downcast_eth_client_state<
    const SYNC_COMMITTEE_SIZE: usize,
    const EXECUTION_PAYLOAD_TREE_DEPTH: usize,
>(
    cs: &dyn Ics2ClientState,
) -> Result<&ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>, ClientError> {
    cs.as_any()
        .downcast_ref::<ClientState<SYNC_COMMITTEE_SIZE, EXECUTION_PAYLOAD_TREE_DEPTH>>()
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

fn trim_left_zero(value: &[u8]) -> &[u8] {
    let mut pos = 0;
    for v in value {
        if *v != 0 {
            break;
        }
        pos += 1;
    }
    &value[pos..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{macros::datetime, OffsetDateTime};

    #[test]
    fn test_trusting_period_validation() {
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = datetime!(2023-08-20 0:00 UTC);
            let trusted_state_timestamp = datetime!(2023-08-20 0:00 UTC);
            validate_and_assert_no_error(
                current_timestamp,
                1,
                1,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
        }

        // trusting_period
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = current_timestamp - Duration::new(0, 1);
            let trusted_state_timestamp = untrusted_header_timestamp - Duration::new(0, 1);
            validate_and_assert_trusting_period_error(
                current_timestamp,
                1,
                0,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
            validate_and_assert_trusting_period_error(
                current_timestamp,
                2,
                0,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
            validate_and_assert_no_error(
                current_timestamp,
                3,
                0,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
        }

        // clock drift
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = current_timestamp + Duration::new(0, 1);
            let trusted_state_timestamp = current_timestamp;
            validate_and_assert_clock_drift_error(
                current_timestamp,
                1,
                0,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
            validate_and_assert_clock_drift_error(
                current_timestamp,
                1,
                1,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
            validate_and_assert_no_error(
                current_timestamp,
                1,
                2,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
        }
    }

    fn validate_and_assert_no_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_within_trusting_period(
            Timestamp::from_nanoseconds(current_timestamp.unix_timestamp_nanos() as u64).unwrap(),
            Duration::from_nanos(trusting_period),
            Duration::from_nanos(clock_drift),
            Timestamp::from_nanoseconds(untrusted_header_timestamp.unix_timestamp_nanos() as u64)
                .unwrap(),
            Timestamp::from_nanoseconds(trusted_state_timestamp.unix_timestamp_nanos() as u64)
                .unwrap(),
        );
        assert!(result.is_ok());
    }

    fn validate_and_assert_trusting_period_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_within_trusting_period(
            Timestamp::from_nanoseconds(current_timestamp.unix_timestamp_nanos() as u64).unwrap(),
            Duration::from_nanos(trusting_period),
            Duration::from_nanos(clock_drift),
            Timestamp::from_nanoseconds(untrusted_header_timestamp.unix_timestamp_nanos() as u64)
                .unwrap(),
            Timestamp::from_nanoseconds(trusted_state_timestamp.unix_timestamp_nanos() as u64)
                .unwrap(),
        );
        if let Err(e) = result {
            match e {
                Error::OutOfTrustingPeriod {
                    current_timestamp: _,
                    trusting_period_end: _,
                } => {}
                _ => panic!("unexpected error: {e}"),
            }
        } else {
            panic!("expected error");
        }
    }

    fn validate_and_assert_clock_drift_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_within_trusting_period(
            Timestamp::from_nanoseconds(current_timestamp.unix_timestamp_nanos() as u64).unwrap(),
            Duration::from_nanos(trusting_period),
            Duration::from_nanos(clock_drift),
            Timestamp::from_nanoseconds(untrusted_header_timestamp.unix_timestamp_nanos() as u64)
                .unwrap(),
            Timestamp::from_nanoseconds(trusted_state_timestamp.unix_timestamp_nanos() as u64)
                .unwrap(),
        );
        if let Err(e) = result {
            match e {
                Error::HeaderFromFuture {
                    current_timestamp: _,
                    clock_drift: _,
                    header_timestamp: _,
                } => {}
                _ => panic!("unexpected error: {e}"),
            }
        } else {
            panic!("expected error");
        }
    }
}
