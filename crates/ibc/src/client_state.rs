use crate::commitment::{calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof};
use crate::consensus_state::{ConsensusState, TrustedConsensusState};
use crate::errors::Error;
use crate::header::Header;
use crate::misbehaviour::Misbehaviour;
use crate::types::AccountUpdateInfo;
use crate::update::apply_updates;
use crate::{eth_client_type, internal_prelude::*};
use core::time::Duration;
use ethereum_consensus::beacon::{Epoch, Root, Slot, Version};
use ethereum_consensus::fork::{ForkParameter, ForkParameters, ForkSpec, BELLATRIX_INDEX};
use ethereum_consensus::types::{Address, H256, U64};
use ethereum_ibc_proto::ibc::lightclients::ethereum::v1::{
    ClientState as RawClientState, Fork as RawFork, ForkSpec as RawForkSpec,
};
use ethereum_light_client_verifier::consensus::SyncProtocolVerifier;
use ethereum_light_client_verifier::context::{
    ChainConsensusVerificationContext, Fraction, LightClientContext,
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

/// The revision number for the Ethereum light client is always 0.
///
/// Therefore, in ethereum, the revision number is not used to determine the hard fork.
/// The current fork is determined by the client state's fork parameters.
pub const ETHEREUM_CLIENT_REVISION_NUMBER: u64 = 0;
pub const ETHEREUM_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.ethereum.v1.ClientState";
pub const ETHEREUM_ACCOUNT_STORAGE_ROOT_INDEX: usize = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState<const SYNC_COMMITTEE_SIZE: usize> {
    // Verification parameters
    /// `genesis_validators_root` of the target beacon chain's BeaconState
    pub genesis_validators_root: Root,
    /// https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/specs/altair/light-client/sync-protocol.md#misc
    pub min_sync_committee_participants: U64,
    /// `genesis_time` of the target beacon chain's BeaconState
    pub genesis_time: U64,
    /// fork parameters of the target beacon chain
    pub fork_parameters: ForkParameters,
    /// https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/configs/mainnet.yaml#L69
    pub seconds_per_slot: U64,
    /// https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/presets/mainnet/phase0.yaml#L36
    pub slots_per_epoch: Slot,
    /// https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/presets/mainnet/altair.yaml#L18
    pub epochs_per_sync_committee_period: Epoch,

    /// An address of IBC contract on execution layer
    pub ibc_address: Address,
    /// The IBC contract's base storage location for storing commitments
    /// https://github.com/hyperledger-labs/yui-ibc-solidity/blob/0e83dc7aadf71380dae6e346492e148685510663/docs/architecture.md#L46
    pub ibc_commitments_slot: H256,

    /// `trust_level` is threshold of sync committee participants to consider the attestation as valid. Highly recommended to be 2/3.
    pub trust_level: Fraction,
    /// `trusting_period` is the period in which the consensus state is considered trusted
    pub trusting_period: Duration,
    /// `max_clock_drift` defines how much new finalized header's time can drift into the future
    pub max_clock_drift: Duration,

    // State
    /// The latest block number of the stored consensus state
    pub latest_execution_block_number: U64,
    /// `frozen_height` is the height at which the client is considered frozen. If `None`, the client is unfrozen.
    pub frozen_height: Option<Height>,

    // Verifiers
    #[serde(skip)]
    pub consensus_verifier:
        SyncProtocolVerifier<SYNC_COMMITTEE_SIZE, TrustedConsensusState<SYNC_COMMITTEE_SIZE>>,
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
    ) -> impl ChainConsensusVerificationContext {
        let current_timestamp = U64::from(
            vctx.host_timestamp()
                .unwrap()
                .into_tm_time()
                .unwrap()
                .unix_timestamp() as u64,
        );
        LightClientContext::new(
            self.fork_parameters.clone(),
            self.seconds_per_slot,
            self.slots_per_epoch,
            self.epochs_per_sync_committee_period,
            self.genesis_time,
            self.genesis_validators_root,
            self.min_sync_committee_participants.0 as usize,
            self.trust_level.clone(),
            current_timestamp,
        )
    }

    pub fn verify_account_storage(
        &self,
        state_root: H256,
        account_update: &AccountUpdateInfo,
    ) -> Result<(), Error> {
        match self
            .execution_verifier
            .verify_account(
                state_root,
                &self.ibc_address,
                account_update.account_proof.clone(),
            )
            .map_err(|e| {
                Error::MPTVerificationError(
                    e,
                    state_root,
                    hex::encode(self.ibc_address.0),
                    account_update
                        .account_proof
                        .iter()
                        .map(hex::encode)
                        .collect(),
                )
            })? {
            Some(account) => {
                if account_update.account_storage_root == account.storage_root {
                    Ok(())
                } else {
                    Err(Error::AccountStorageRootMismatch(
                        account_update.account_storage_root,
                        account.storage_root,
                        state_root,
                        hex::encode(self.ibc_address.0),
                        account_update
                            .account_proof
                            .iter()
                            .map(hex::encode)
                            .collect(),
                    ))
                }
            }
            None => {
                if account_update.account_storage_root.is_zero() {
                    Ok(())
                } else {
                    Err(Error::AccountStorageRootMismatch(
                        account_update.account_storage_root,
                        H256::default(),
                        state_root,
                        hex::encode(self.ibc_address.0),
                        account_update
                            .account_proof
                            .iter()
                            .map(hex::encode)
                            .collect(),
                    ))
                }
            }
        }
    }

    pub fn verify_membership(
        &self,
        proof_height: ibc::Height,
        _counterparty_prefix: &ibc::core::ics23_commitment::commitment::CommitmentPrefix,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        path: impl Into<Path>,
        value: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.verify_height(proof_height)?;
        let proof = decode_eip1184_rlp_proof(proof.clone().into())?;
        let path = path.into();
        let root = H256::from_slice(root.as_bytes());
        // if root is zero, the IBC contract has not been initialized yet
        if root.is_zero() {
            return Err(ClientError::ClientSpecific {
                description: format!(
                    "failed to verify membership: root is zero: path={} value={:?}",
                    path, value
                ),
            });
        }
        let key = calculate_ibc_commitment_storage_key(&self.ibc_commitments_slot, path.clone());
        self.execution_verifier
            .verify_membership(
                root,
                key.as_bytes(),
                rlp::encode(&trim_left_zero(&value)).as_ref(),
                proof.clone(),
            )
            .map_err(|e| ClientError::ClientSpecific {
                description: format!(
                    "failed to verify membership: path={} root={} value={:?} proof={:?} error={}",
                    path, root, value, proof, e
                ),
            })?;
        Ok(())
    }

    pub fn verify_non_membership(
        &self,
        proof_height: ibc::Height,
        _counterparty_prefix: &ibc::core::ics23_commitment::commitment::CommitmentPrefix,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        path: impl Into<Path>,
    ) -> Result<(), ibc::core::ics02_client::error::ClientError> {
        self.verify_height(proof_height)?;
        let proof = decode_eip1184_rlp_proof(proof.clone().into())?;
        let path = path.into();
        let root = H256::from_slice(root.as_bytes());
        // if root is zero, the IBC contract has not been initialized yet
        if root.is_zero() {
            return Err(ClientError::ClientSpecific {
                description: format!(
                    "failed to verify non-membership: root is zero: path={}",
                    path
                ),
            });
        }
        let key = calculate_ibc_commitment_storage_key(&self.ibc_commitments_slot, path.clone());
        self.execution_verifier
            .verify_non_membership(root, key.as_bytes(), proof.clone())
            .map_err(|e| ClientError::ClientSpecific {
                description: format!(
                    "failed to verify non-membership: path={} root={} proof={:?} error={}",
                    path, root, proof, e
                ),
            })?;
        Ok(())
    }

    /// Verify that the client is at a sufficient height and unfrozen
    pub fn verify_height(&self, height: Height) -> Result<(), Error> {
        if height.revision_number() != ETHEREUM_CLIENT_REVISION_NUMBER {
            return Err(Error::UnexpectedHeightRevisionNumber {
                expected: ETHEREUM_CLIENT_REVISION_NUMBER,
                got: height.revision_number(),
            });
        }
        if self.is_frozen() {
            return Err(Error::ClientFrozen {
                frozen_height: self.frozen_height.unwrap(),
                target_height: height,
            });
        }
        if self.latest_height() < height {
            return Err(Error::InsufficientHeight {
                latest_height: self.latest_height(),
                target_height: height,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Error> {
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
        } else if self.fork_parameters.forks().len() <= BELLATRIX_INDEX {
            Err(Error::MissingBellatrixFork)
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
        } else if self.latest_execution_block_number == U64::default() {
            Err(Error::UninitializedClientStateField(
                "latest_execution_block_number",
            ))
        } else {
            Ok(())
        }
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> Ics2ClientState for ClientState<SYNC_COMMITTEE_SIZE> {
    fn client_type(&self) -> ClientType {
        eth_client_type()
    }

    fn latest_height(&self) -> Height {
        Height::new(
            ETHEREUM_CLIENT_REVISION_NUMBER,
            self.latest_execution_block_number.into(),
        )
        .unwrap()
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height
    }

    fn initialise(
        &self,
        consensus_state: Any,
    ) -> Result<Box<dyn Ics02ConsensusState>, ClientError> {
        self.validate()?;
        if self.is_frozen() {
            return Err(Error::CannotInitializeFrozenClient.into());
        }
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
        if self.is_frozen() {
            return Err(ClientError::ClientFrozen { client_id });
        }
        let cc = self.build_context(ctx);
        let header = Header::<SYNC_COMMITTEE_SIZE>::try_from(header)?;
        header.validate(&cc)?;

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
            consensus_state.clone(),
            trusted_sync_committee.sync_committee,
            trusted_sync_committee.is_next,
        )?;

        let consensus_update = header.consensus_update;
        let execution_update = header.execution_update;
        let account_update = header.account_update;
        let header_timestamp = header.timestamp;

        self.consensus_verifier
            .validate_updates(
                &cc,
                &trusted_consensus_state,
                &consensus_update,
                &execution_update,
            )
            .map_err(Error::VerificationError)?;

        self.verify_account_storage(execution_update.state_root, &account_update)?;

        let host_timestamp = ctx
            .host_timestamp()
            .map_err(|e| ClientError::ClientSpecific {
                description: e.to_string(),
            })?;
        // check if the current timestamp is within the trusting period
        validate_state_timestamp_within_trusting_period(
            host_timestamp,
            self.trusting_period,
            consensus_state.timestamp,
        )?;
        // check if the header timestamp does not indicate a future time
        validate_header_timestamp_not_future(
            host_timestamp,
            self.max_clock_drift,
            header_timestamp,
        )?;

        let (new_client_state, new_consensus_state) = apply_updates(
            &cc,
            self,
            &consensus_state,
            consensus_update,
            execution_update.block_number,
            account_update.account_storage_root,
            header_timestamp,
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
        if self.is_frozen() {
            return Err(ClientError::ClientFrozen { client_id }.into());
        }
        let misbehaviour = Misbehaviour::<SYNC_COMMITTEE_SIZE>::try_from(misbehaviour)?;
        misbehaviour.validate()?;
        if misbehaviour.client_id != client_id {
            return Err(
                Error::UnexpectedClientIdInMisbehaviour(client_id, misbehaviour.client_id).into(),
            );
        }

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
            consensus_state.clone(),
            misbehaviour.trusted_sync_committee.sync_committee,
            misbehaviour.trusted_sync_committee.is_next,
        )?;

        self.consensus_verifier
            .validate_misbehaviour(&cc, &trusted_consensus_state, misbehaviour.data)
            .map_err(Error::VerificationError)?;

        let host_timestamp = ctx
            .host_timestamp()
            .map_err(|e| ClientError::ClientSpecific {
                description: e.to_string(),
            })?;
        validate_state_timestamp_within_trusting_period(
            host_timestamp,
            self.trusting_period,
            consensus_state.timestamp,
        )?;

        // found misbehaviour
        Ok(self
            .clone()
            .with_frozen_height(misbehaviour.trusted_sync_committee.height)
            .into_box())
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
        let value = expected_consensus_state
            .encode_vec()
            .map_err(ClientError::InvalidAnyConsensusState)?;
        self.verify_membership(
            proof_height,
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
        let value = expected_counterparty_connection_end
            .encode_vec()
            .map_err(ClientError::InvalidConnectionEnd)?;
        self.verify_membership(
            proof_height,
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
        let value = expected_counterparty_channel_end
            .encode_vec()
            .map_err(ClientError::InvalidChannelEnd)?;

        self.verify_membership(
            proof_height,
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
        let value = expected_client_state.encode_to_vec();

        self.verify_membership(
            proof_height,
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
        proof_height: ibc::Height,
        connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        commitment_path: &ibc::core::ics24_host::path::CommitmentPath,
        commitment: ibc::core::ics04_channel::commitment::PacketCommitment,
    ) -> Result<(), ClientError> {
        self.verify_membership(
            proof_height,
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
        proof_height: ibc::Height,
        connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        ack_path: &ibc::core::ics24_host::path::AckPath,
        ack: ibc::core::ics04_channel::commitment::AcknowledgementCommitment,
    ) -> Result<(), ClientError> {
        self.verify_membership(
            proof_height,
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
        proof_height: ibc::Height,
        connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        seq_recv_path: &ibc::core::ics24_host::path::SeqRecvPath,
        sequence: ibc::core::ics04_channel::packet::Sequence,
    ) -> Result<(), ClientError> {
        let mut seq_bytes = Vec::new();
        u64::from(sequence)
            .encode(&mut seq_bytes)
            .expect("buffer size too small");

        self.verify_membership(
            proof_height,
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
        proof_height: ibc::Height,
        connection_end: &ibc::core::ics03_connection::connection::ConnectionEnd,
        proof: &ibc::core::ics23_commitment::commitment::CommitmentProofBytes,
        root: &ibc::core::ics23_commitment::commitment::CommitmentRoot,
        receipt_path: &ibc::core::ics24_host::path::ReceiptPath,
    ) -> Result<(), ClientError> {
        self.verify_non_membership(
            proof_height,
            connection_end.counterparty().prefix(),
            proof,
            root,
            receipt_path.clone(),
        )
    }

    // `chain_id`, `expired`, `zero_custom_fields`, `verify_upgrade_client`, `update_state_with_upgrade_client` are not supported for Ethereum client

    fn chain_id(&self) -> ChainId {
        unimplemented!()
    }

    #[allow(unused_variables)]
    fn expired(&self, elapsed: Duration) -> bool {
        unimplemented!()
    }

    fn zero_custom_fields(&mut self) {
        unimplemented!()
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
        unimplemented!()
    }

    #[allow(unused_variables)]
    fn update_state_with_upgrade_client(
        &self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
    ) -> Result<UpdatedState, ClientError> {
        unimplemented!()
    }
}

fn validate_state_timestamp_within_trusting_period(
    current_timestamp: Timestamp,
    trusting_period: Duration,
    trusted_consensus_state_timestamp: Timestamp,
) -> Result<(), Error> {
    let trusting_period_end = (trusted_consensus_state_timestamp + trusting_period)?;
    if !trusting_period_end.after(&current_timestamp) {
        return Err(Error::OutOfTrustingPeriod {
            current_timestamp,
            trusting_period_end,
        });
    }
    Ok(())
}

fn validate_header_timestamp_not_future(
    current_timestamp: Timestamp,
    clock_drift: Duration,
    untrusted_header_timestamp: Timestamp,
) -> Result<(), Error> {
    let drifted_current_timestamp = (current_timestamp + clock_drift)?;
    if !drifted_current_timestamp.after(&untrusted_header_timestamp) {
        return Err(Error::HeaderFromFuture {
            current_timestamp,
            clock_drift,
            header_timestamp: untrusted_header_timestamp,
        });
    }
    Ok(())
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

        fn convert_fork_spec(idx: usize, spec: Option<RawForkSpec>) -> Result<ForkSpec, Error> {
            if let Some(spec) = spec {
                Ok(ForkSpec {
                    finalized_root_gindex: spec.finalized_root_gindex,
                    current_sync_committee_gindex: spec.current_sync_committee_gindex,
                    next_sync_committee_gindex: spec.next_sync_committee_gindex,
                    execution_payload_gindex: spec.execution_payload_gindex,
                    execution_payload_state_root_gindex: spec.execution_payload_state_root_gindex,
                    execution_payload_block_number_gindex: spec
                        .execution_payload_block_number_gindex,
                })
            } else {
                Err(Error::proto_missing(&format!("forks[{}].spec", idx)))
            }
        }

        let raw_fork_parameters = value
            .fork_parameters
            .ok_or(Error::proto_missing("fork_parameters"))?;
        let fork_parameters: ForkParameters = ForkParameters::new(
            bytes_to_version(raw_fork_parameters.genesis_fork_version),
            raw_fork_parameters
                .forks
                .into_iter()
                .enumerate()
                .map(|(i, f)| -> Result<_, Error> {
                    Ok(ForkParameter::new(
                        bytes_to_version(f.version),
                        f.epoch.into(),
                        convert_fork_spec(i, f.spec)?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(Error::EthereumConsensusError)?;
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
            latest_execution_block_number: value.latest_execution_block_number.into(),
            frozen_height,
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

        fn make_fork(version: &Version, epoch: U64, spec: ForkSpec) -> RawFork {
            RawFork {
                version: version_to_bytes(version),
                epoch: epoch.into(),
                spec: Some(RawForkSpec {
                    finalized_root_gindex: spec.finalized_root_gindex,
                    current_sync_committee_gindex: spec.current_sync_committee_gindex,
                    next_sync_committee_gindex: spec.next_sync_committee_gindex,
                    execution_payload_gindex: spec.execution_payload_gindex,
                    execution_payload_state_root_gindex: spec.execution_payload_state_root_gindex,
                    execution_payload_block_number_gindex: spec
                        .execution_payload_block_number_gindex,
                }),
            }
        }

        fn version_to_bytes(version: &Version) -> Vec<u8> {
            version.0.to_vec()
        }

        let fork_parameters = value.fork_parameters;

        Self {
            genesis_validators_root: value.genesis_validators_root.as_bytes().to_vec(),
            min_sync_committee_participants: value.min_sync_committee_participants.into(),
            genesis_time: value.genesis_time.into(),
            fork_parameters: Some(ProtoForkParameters {
                genesis_fork_version: version_to_bytes(fork_parameters.genesis_version()),
                forks: fork_parameters
                    .forks()
                    .iter()
                    .map(|f| make_fork(&f.version, f.epoch, f.spec.clone()))
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

fn downcast_eth_consensus_state(
    cs: &dyn Ics02ConsensusState,
) -> Result<ConsensusState, ClientError> {
    cs.as_any()
        .downcast_ref::<ConsensusState>()
        .ok_or_else(|| ClientError::ClientArgsTypeMismatch {
            client_type: eth_client_type(),
        })
        .cloned()
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
    use ethereum_consensus::fork::{
        altair::ALTAIR_FORK_SPEC, bellatrix::BELLATRIX_FORK_SPEC, capella::CAPELLA_FORK_SPEC,
        deneb::DENEB_FORK_SPEC,
    };
    use ethereum_consensus::preset::minimal::PRESET;
    use hex_literal::hex;
    use time::{macros::datetime, OffsetDateTime};

    #[test]
    fn test_client_state_conversion() {
        let client_state =
            ClientState::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }> {
                genesis_validators_root: keccak256("genesis_validators_root"),
                min_sync_committee_participants: 1.into(),
                genesis_time: 1.into(),
                fork_parameters: ForkParameters::new(
                    Version([0, 0, 0, 1]),
                    vec![
                        ForkParameter::new(Version([1, 0, 0, 1]), U64(0), ALTAIR_FORK_SPEC),
                        ForkParameter::new(Version([2, 0, 0, 1]), U64(0), BELLATRIX_FORK_SPEC),
                        ForkParameter::new(Version([3, 0, 0, 1]), U64(0), CAPELLA_FORK_SPEC),
                        ForkParameter::new(Version([4, 0, 0, 1]), U64(0), DENEB_FORK_SPEC),
                    ],
                )
                .unwrap(),
                seconds_per_slot: PRESET.SECONDS_PER_SLOT,
                slots_per_epoch: PRESET.SLOTS_PER_EPOCH,
                epochs_per_sync_committee_period: PRESET.EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
                ibc_address: Address(hex!("ff77D90D6aA12db33d3Ba50A34fB25401f6e4c4F")),
                ibc_commitments_slot: keccak256("ibc_commitments_slot"),
                trust_level: Fraction::new(2, 3),
                trusting_period: Duration::from_secs(60 * 60 * 27),
                max_clock_drift: Duration::from_secs(60),
                latest_execution_block_number: 1.into(),
                frozen_height: None,
                consensus_verifier: Default::default(),
                execution_verifier: Default::default(),
            };
        let res = client_state.validate();
        assert!(res.is_ok(), "{:?}", res);

        let any_client_state: Any = client_state.clone().into();
        let client_state2 = ClientState::try_from(any_client_state).unwrap();
        assert_eq!(client_state, client_state2);

        // Unexpected fork parameters
        let mut client_state = client_state.clone();
        client_state.fork_parameters = ForkParameters::new(
            Version([0, 0, 0, 1]),
            vec![ForkParameter::new(
                Version([1, 0, 0, 1]),
                U64(0),
                ALTAIR_FORK_SPEC,
            )],
        )
        .unwrap();
        let res = client_state.validate();
        assert!(res.is_err(), "{:?}", res);
    }

    #[test]
    fn test_verify_account_storage() {
        let client_state =
            ClientState::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }> {
                ibc_address: Address(hex!("ff77D90D6aA12db33d3Ba50A34fB25401f6e4c4F")),
                ..Default::default()
            };
        let account_proof = decode_eip1184_rlp_proof(
            hex!("f901fff90191a05844e303fa8db3fa31c729db25d9b593367f853b4cbcb1a91fc85eda11e16617a09bb111cd80eee4c6ae6af0d01422ae82fccfa80d0267c4c8d525bc7f2b6233afa0323230228b1ba9b7eb88084b6d1ed9b75813a2da2d5ff0df9067335f5f55444ca0bfca1461a76f96944aa00afff03dc8de770275fbbe360f6ee03b0fe0ce902fd8a04c7579812e09de2b1aa746b0a047d357e898e9d634ac185d7e9d25b3d2336ab3808080a0c7de43d788c5228ebde29b62cb0f9b9eb10c0cb9b1078d6a51f768e0cdf296d6a0b8ad2523a3d1fdf33b627f598622775508297710e3623de115f2174c7f5727dfa023910890abfb016861bb7916cb555add80e552f118c0f1b93ec7d26798976f1da077153f3a45bebfb8b6709bd52e71d0993e9ecfd4e425204e258e5e5ac775ee73a01b42efb18b5af3defc59ba21f68965c5a28c716e109df937d216a2041fee4770a06b4b8f8ad0ae7588581c191bf177d5020fcc0f9152123cd26b3acf4e3469744280a0b4ec201ec80c64cefbe351f2febea48eb21c0d65d3e1c868178ece65e3d63ff480f869a0346090ccaa6fa9fa12360268a84aaba21af051a53bfdc84493350c840f61b79eb846f8440180a0d70e9391a3dd508a60195d2a5e12fb2f7e49582f9ce2c12477299377ccfadaada073092abb9be4a3fa206fd43699af07ff9d4278c27693f013fceb7780f3654c09").to_vec()
        ).unwrap();
        let res = client_state.verify_account_storage(
            H256(hex!(
                "48b7747ba1094684d9197bbaa5dcb134587d23e493fb53a29e400c50e50f5147"
            )),
            &AccountUpdateInfo {
                account_proof,
                account_storage_root: H256(hex!(
                    "d70e9391a3dd508a60195d2a5e12fb2f7e49582f9ce2c12477299377ccfadaad"
                )),
            },
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn test_verify_account_storage_non_existence() {
        let client_state =
            ClientState::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE }> {
                ibc_address: Address(hex!("a7f733a4fEA1071f58114b203F57444969b86524")),
                ..Default::default()
            };
        let account_proof = decode_eip1184_rlp_proof(
            hex!("f90c8bf90211a0735c089329da81ce7b2d42666be5a1937cba65e1e018ca007d2d89097643093da050ac94d9d3f41b5affc198a6fe058bbf0b5c325da0bc89914e94cd792c835ec7a0dd6fafef2a8250c254db15fa44c2d53dc543eddb86800bcd892bd98c0adb2fafa0603d4baa1bf91623b90e4d7760123036058fabdc5895f1efab03d9bc9b92da9ea0688c8a3f57cf3579a8b19011d9a811e5bcbcd467216935fdfde60884e6af7991a0812a0308609cc2b529630ab727abd3b1aa974896e4cd0a02bbe517f77b142a2ba02904a77c6e9c680d4d302e5a51b847fca63a6532b21b07dd41a3ac49f4151349a0e179454a28109b5aab7b880693b5786b568781d9aa45986f74be7d6a7a818d72a07f3363c3908198f0aaa22c64185be10461a51524bc2b53f5d622caef25c672a0a0e65b893234155029bcf2f893bfdf4498509062c0949eb0ffc027c075267b999fa01d6a1e0b72b63a7a00083a40572d4041116a286fa3a2d747b25fa0cefe07642ca0d8b29fe0f182ddf0482f5b3ab6b3a0640e63177a78eadf75f5773ed534214e4aa0de1d7bd5c5dbc04a2f734621a7225856c722cce92fe201cab1348282b05a1d97a0f9e111c8222ff2bc2fe565ff7f626c9748239c2038e288380081eb2a3af0c908a07dd132ff024cf49ed3f49149f8bae764e9a173f499ccfcd9f408dd2000bb531da0b954951fd86e5b275c759fbd29eaa292f3c84fdbb6bcc5b1e714a1d838582aae80f90211a04d152a07d2c9c1547501953755563814d7cb184a7756551eaf482b759dae5769a07316575d385637101fdb5f52e676e10f25ae0aa08eee125a7e5bedf4aad6c122a011e2f69401bab09a648aff06e1893c93e2e58a9635d0bcbeb56ae3f585a04b85a086e49bb50598013f14675177ae79c1da54e6c2bbaf91c3b1341142c29271c409a0ceff5f5bd8e1824b24651f15e4ba56fee26cb0b9173f7d4ebab3e0293c7269e7a0fecedf695e9918f9c3397accb5416c4696999fa64fa2e842ec79be8cb93a8651a0854ca3709cc3460ada39aea9619d7f571c117b6054ecb2c4370584d63cf03641a0826eff5d12e4895656e42b47bb3ae6d82027b210c09c85ea702c117193beab3da009fe1cc705eb0d3ac788027f618c076ef1510aadcee6cd736ac931c763f9ef67a0cafc24169ce2d0bc3a14471e1d74470cf692df45e672a4b5281be6634d0f06f4a06dd0a6ae12c583185056c34a27b4df3e66b7da685d90b05e05f73e4904dd502aa0a43f00480c0a7219aca6e9681573abe0206a0ac744fddbd721a00d9342bbc418a0f97f13efdb911e697b75663c41dca7e5b31ad93a6d460bac224e30c1188fb7e3a07fc2f215ae82e3c19b48ec6f1a28427f17a04668308f573c20b68626bc85955ca04896f54096f0489f5d0649b4d7fc796caccfbb275dfa1a90b8b9be2116a7e273a0cdbca11f9ed5ea1d347dd6f40c8bdb8505f21deb53161ea57ebd08fe0becfa8f80f90211a03bf4c6b5933c499c155a6edb44b781dc408992c2c4c16ca1d75ad19e23fafeefa0b55c56b13f5d19dde3d7d96cc156a92d2feb78d29125f9bd2925202f466313a7a0244e4254c915f0209716c58e02b1e59702b3b9a28c5c59d361dd06cd91ec70f9a06ea7d219827e2a71031d36d892fffb6aca878ec90f0e1086cbf6a5dd1ff8763ba0751e39cd8c27f3607a42d11897cd190d0984be5847cbe6100751d06d04c637bba002871c10a84f539119d02559afcc35d6751864529189ce5c7038a2c118601fe3a0306ff9c515871b0080b9334022351644dbe44901c2b2f267311675829c1307fca0a963d8f5da27142226b9607bd09d1aa7d64f3615236bc22cb7439045b0d93abea0e91fb125186252297f099d76d4f40ee948d5a0fb2b469ee63c685db204be7a4ca0ccd4667345dd458431de1d9fab425f36553d444e9b059d847d72b4a193971f1aa0d3b2c96703267e6040450109d4226f4b05cd4274c5f4ed99aa97b83b70044bf1a0543e2abdea1838ca8408ac52fb1d7fb170b2e822aa6989558d4fbf47a0f8b851a016b137139bdb068d710119ec01df37f40e6c6db0c31346bf083893a73e3402e0a070ef51e27ac486580d225c4f7bb73f6456f2fbc69ea5e945471d9c86268d3da4a0838f376bf27fbe43dcede5396b787b4047ab9ab13c3d54b71ea7ded3aeb44ef1a02c207350ede911a939db2cbde3644c5508592fe281d97b7f798753779ae6651a80f90211a04081815e12cf03a52f183def5e687076094b0bc6387363c051b3e4b1be4d1d19a06c73c48b7349672f346b03a3df4838129ed5f92eddddd7e2d1e2efad591602cba0b78231ff87a3f6b239661cde00ea1f605e78a70886467d2fba5ec455327182a4a00e844f2238c3a9a7401aacd5382fd8e9ade8c5d9a2ed18936f18b7a4a0ce0159a0f0cf87ad75cbe0d422d501ceecd3eeb2322e987dd06b948719296214d2b1bd3da0b972c5937a9fc152bc6fa930e84060e2bef4a63d83978a4ec6bc14b60bf452efa0db85e78720006b5ea6e7b258522837815cfb16a3c634e74913394239fb83397ea0f79388ee57552bb0f2cd6fb7fcb716156607be0f95acdab409b64f590c7d7f72a0140623eb8411a98ac14271b6838908e6a27803bfea3073aef8c8825eaed50fe1a09400f4a94faf9a7a80d58f889ca08a665c82e1cac2039a7fcc0ae9698621f1e0a0ebb02920f9288829afb95192e7466da33e45f996d9cd29d7fc06cad275663d47a0dfd361a59760d8542085eb26b3108ccda0111407637599dfd6ee1db3f8d7829ea07bfd10a32a6183ace7f87df01d5dc24bf0e9d09f65e7954096ab6386ac72bf3fa056a0b81e9ddedb42072c3b9100cf911c1933d16e231dde74647d33b7e8de95b7a0ed1a49b7ed1daea815c0cb7400776af17dbc4b27300cffc5c5d61ce01305f6c6a0b98bf6e4aadc8c9f754d04107972e868325c1c0b65338b14e80a8754952c533780f90211a06c58a57085037dfc8db7fcc57396521078f8fcfb9e76eeb2b45d3408c1fdd191a056dcc694badf8487675150d3f90d7452e1d008da178140a84cab3708e94eb4eda06ee4844656a92e04a04a5469280c9d69b4f12ab8f29896b2645fcb92603bea80a0807c0b0f7cdfa86c4390d62202ad4eacfe0a6182189b34bad027db16336c5a78a02b1b7221d0a98161170a5008a702030f8ec84d02f939b59755952ce3437bba0aa01c5e574e042f54cf46caec858db5ca34901a000195d1f044e03dcbb66f904e36a0d0f3ab90005c9f49578bbba90bca526e4034d86d49fde2c8269be58a30f540e3a0145539ee81a9fb21e1af7b5851d57a497765dd5c4351904c8a725ec755e0ce52a0e90a6fd2863da09c2bf1f1a4f0d8f04a095bdc76816000aeaef5bb20e4f717d9a033d95a81d8b601f9dbdbea947a7052eb849dd91875e734da645c9f240418c72fa053dc0376d2c1309c1bbe7755d7ede7bfa4af13c2c933538a539c75bdecbd9e53a0707665486d4924ae7eecfcf41f7f804906140baecf43fa72ec8419bcdfd48f1ba0ccf9006732611705137f5562d6b59442af44c13ea97df11c09df468dbe0a7323a0385c7d72bf637b580a2ddec76007d12d1048a2553ec662d96ed25ccedd97053fa0939aa354a3598e3248baf25e27953c3812b2c555d5e43db59d330ab6f9e8c3c3a0c941eff5b200af34d12362bf73856fa0164d788274804245239e66c55091135080f901b18080a0a3c8aca2eeb300dc458c7fc99aadba23e3bbd0f88e9def4c89c8c58c5e4b468aa02440a82db7c8b7044dd2fba70e5204e481032a630173d8d9752851e7df7e4240a0a60accaa78c07a21cfb1414797e9d8dd1236cf96bb1bb56235ac899906c25bc7a047e97e35f2cd979e6b93001f40002e22a0e754923d6e093c0f7cf2578d460e82a017e89cef18477aa7708df31998c60d1acd734e0266e70d8388914ab6f53d7ce9a000031279827d634f41754800f88bc0e9e134cb2d1d66065493c6ef32f22ed1c6a03bdc555af1c06c2c53d99b142ef0fc72c4b58bbfe63975c1aeda24a3eb2ea66ca06408ef004b300be9baccefd12ee648e24adc85841af0d0037c56c3992a0a5e2d80a0b4c8ba93a4166cfc2a051400b8afcdb41d5c74be9d105fb39613f8d9ab064a4da073f59f57bc2e6297832cb37f6618ba99279e2f32d2661110c1682ed2e8694c7ca056ec3e008e136bdf75ee10371aad81c93e6592dc5224b0b3018fea73bae89f7da01cf891d6aa49256fbe12d75e60adfbc612826164564eb89c19371a2625fb8633a04b147c2c876e2578176a1789f8c80d2c4674fbc6ea1cdd319e4b89085594fc4880f87180808080a0898c7859ae8ec9411296d9568545abbe3395dcab69264d16de52cf2489bea53e808080808080a0fdbf45b5370653412069c67c697029941cc4c34a563d265b2b34f95656cb2a38a06a47e9ff626afe400b0591b2632976db76ff66355e000d89b39fa40c3148934f80808080").to_vec()
        ).unwrap();
        let res = client_state.verify_account_storage(
            H256(hex!(
                "568a51c3253bbd2d46e3923b35df0489712df11453fd04dd71341120356952c0"
            )),
            &AccountUpdateInfo {
                account_proof,
                account_storage_root: H256::default(), // non-existence
            },
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn test_trusting_period_validation() {
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let trusted_state_timestamp = datetime!(2023-08-20 0:00 UTC);
            validate_and_assert_trusting_period_no_error(
                current_timestamp,
                1,
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
                trusted_state_timestamp,
            );
            validate_and_assert_trusting_period_error(
                current_timestamp,
                2,
                trusted_state_timestamp,
            );
            validate_and_assert_trusting_period_no_error(
                current_timestamp,
                3,
                trusted_state_timestamp,
            );
        }

        // clock drift
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = current_timestamp + Duration::new(0, 1);
            validate_and_assert_clock_drift_error(current_timestamp, 0, untrusted_header_timestamp);
            validate_and_assert_clock_drift_error(current_timestamp, 1, untrusted_header_timestamp);
            validate_and_assert_clock_drift_no_error(
                current_timestamp,
                2,
                untrusted_header_timestamp,
            );
        }
    }

    fn validate_and_assert_trusting_period_no_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_state_timestamp_within_trusting_period(
            Timestamp::from_nanoseconds(current_timestamp.unix_timestamp_nanos() as u64).unwrap(),
            Duration::from_nanos(trusting_period),
            Timestamp::from_nanoseconds(trusted_state_timestamp.unix_timestamp_nanos() as u64)
                .unwrap(),
        );
        assert!(result.is_ok());
    }

    fn validate_and_assert_trusting_period_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_state_timestamp_within_trusting_period(
            Timestamp::from_nanoseconds(current_timestamp.unix_timestamp_nanos() as u64).unwrap(),
            Duration::from_nanos(trusting_period),
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

    fn validate_and_assert_clock_drift_no_error(
        current_timestamp: OffsetDateTime,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
    ) {
        let result = validate_header_timestamp_not_future(
            Timestamp::from_nanoseconds(current_timestamp.unix_timestamp_nanos() as u64).unwrap(),
            Duration::from_nanos(clock_drift),
            Timestamp::from_nanoseconds(untrusted_header_timestamp.unix_timestamp_nanos() as u64)
                .unwrap(),
        );
        assert!(result.is_ok());
    }

    fn validate_and_assert_clock_drift_error(
        current_timestamp: OffsetDateTime,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
    ) {
        let result = validate_header_timestamp_not_future(
            Timestamp::from_nanoseconds(current_timestamp.unix_timestamp_nanos() as u64).unwrap(),
            Duration::from_nanos(clock_drift),
            Timestamp::from_nanoseconds(untrusted_header_timestamp.unix_timestamp_nanos() as u64)
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

    #[test]
    fn test_trim_left_zero() {
        assert_eq!(trim_left_zero(&[1, 2, 3, 4]), [1, 2, 3, 4]);
        assert_eq!(trim_left_zero(&[1, 2, 3, 0]), [1, 2, 3, 0]);
        assert_eq!(trim_left_zero(&[0, 2, 3, 0]), [2, 3, 0]);
        assert_eq!(trim_left_zero(&[0, 0, 3, 0]), [3, 0]);
        assert_eq!(trim_left_zero(&[0, 0, 0, 4]), [4]);
        assert!(trim_left_zero(&[0, 0, 0, 0]).is_empty());
        assert!(trim_left_zero(&[]).is_empty());
    }

    fn keccak256(s: &str) -> H256 {
        use tiny_keccak::{Hasher, Keccak};
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(s.as_bytes());
        hasher.finalize(&mut output);
        H256::from_slice(&output)
    }
}
