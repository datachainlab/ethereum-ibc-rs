use crate::{
    client_state::ClientState,
    consensus_state::{ConsensusState, TrustedConsensusState},
    errors::Error,
    internal_prelude::*,
    types::AccountUpdateInfo,
};
use ethereum_consensus::{
    beacon::Slot,
    compute::{compute_sync_committee_period_at_slot, compute_timestamp_at_slot},
    context::ChainContext,
    sync_protocol::EXECUTION_PAYLOAD_DEPTH,
    types::H256,
};
use ethereum_light_client_verifier::state::SyncCommitteeView;
use ibc::timestamp::Timestamp;

pub type LightClientUpdate<const SYNC_COMMITTEE_SIZE: usize> =
    ethereum_consensus::bellatrix::LightClientUpdate<SYNC_COMMITTEE_SIZE>;
pub type ConsensusUpdateInfo<const SYNC_COMMITTEE_SIZE: usize> =
    ethereum_light_client_verifier::updates::bellatrix::ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>;
pub type ExecutionUpdateInfo =
    ethereum_light_client_verifier::updates::bellatrix::ExecutionUpdateInfo;

pub fn new_consensus_update<const SYNC_COMMITTEE_SIZE: usize>(
    light_client_update: LightClientUpdate<SYNC_COMMITTEE_SIZE>,
    finalized_execution_root: H256,
    finalized_execution_branch: Vec<H256>,
) -> ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE> {
    let mut branch: [H256; EXECUTION_PAYLOAD_DEPTH] = Default::default();
    branch.clone_from_slice(&finalized_execution_branch);
    ConsensusUpdateInfo {
        light_client_update,
        finalized_execution_root,
        finalized_execution_branch: branch,
    }
}

pub fn apply_updates<const SYNC_COMMITTEE_SIZE: usize, C: ChainContext>(
    ctx: &C,
    client_state: &ClientState<SYNC_COMMITTEE_SIZE>,
    trusted_consensus_state: &TrustedConsensusState<SYNC_COMMITTEE_SIZE>,
    consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    execution_update: ExecutionUpdateInfo,
    account_update: AccountUpdateInfo,
    timestamp: Timestamp,
) -> Result<(ClientState<SYNC_COMMITTEE_SIZE>, ConsensusState), Error> {
    let mut new_client_state = client_state.clone();

    let store_period =
        compute_sync_committee_period_at_slot(ctx, trusted_consensus_state.current_slot());
    let update_period = compute_sync_committee_period_at_slot(
        ctx,
        consensus_update.light_client_update.finalized_header.0.slot,
    );
    let timestamp = timestamp.into_tm_time().unwrap().unix_timestamp() as u64;
    let finalized_header_timestamp: u64 = compute_timestamp_at_slot(
        ctx,
        consensus_update.light_client_update.finalized_header.0.slot,
    )
    .into();
    if finalized_header_timestamp != timestamp {
        return Err(Error::UnexpectedTimestamp(
            finalized_header_timestamp,
            timestamp,
        ));
    }

    if client_state.latest_slot < consensus_update.light_client_update.finalized_header.0.slot {
        new_client_state.latest_slot = consensus_update.light_client_update.finalized_header.0.slot;
    }
    if client_state.latest_execution_block_number < execution_update.block_number {
        new_client_state.latest_execution_block_number = execution_update.block_number;
    }

    let new_consensus_state = if store_period == update_period {
        ConsensusState {
            slot: consensus_update.light_client_update.finalized_header.0.slot,
            storage_root: account_update.account_storage_root.0.to_vec().into(),
            timestamp: wrap_compute_timestamp_at_slot(
                ctx,
                consensus_update.light_client_update.finalized_header.0.slot,
            )?,
            current_sync_committee: trusted_consensus_state.current_sync_committee_aggregate_key(),
            next_sync_committee: consensus_update
                .light_client_update
                .next_sync_committee
                .as_ref()
                .map(|c| c.0.aggregate_pubkey.clone()),
        }
    } else if store_period + 1 == update_period {
        ConsensusState {
            slot: consensus_update.light_client_update.finalized_header.0.slot,
            storage_root: account_update.account_storage_root.0.to_vec().into(),
            timestamp: wrap_compute_timestamp_at_slot(
                ctx,
                consensus_update.light_client_update.finalized_header.0.slot,
            )?,
            current_sync_committee: trusted_consensus_state
                .next_sync_committee()
                .as_ref()
                .unwrap()
                .aggregate_pubkey
                .clone(),
            next_sync_committee: consensus_update
                .light_client_update
                .next_sync_committee
                .as_ref()
                .map(|c| c.0.aggregate_pubkey.clone()),
        }
    } else {
        // store_period + 1 < update_period
        return Err(Error::FuturePeriodError(store_period, update_period));
    };

    Ok((new_client_state, new_consensus_state))
}

fn wrap_compute_timestamp_at_slot<C: ChainContext>(
    ctx: &C,
    slot: Slot,
) -> Result<Timestamp, Error> {
    // NOTE: The return value of `compute_timestamp_at_slot`'s unit is seconds,
    // so we need to convert it to nanoseconds.
    let timestamp = compute_timestamp_at_slot(ctx, slot);
    Ok(Timestamp::from_nanoseconds(timestamp.0 * 1_000_000_000)?)
}
