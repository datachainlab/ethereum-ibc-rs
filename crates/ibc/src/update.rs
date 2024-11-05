use crate::{
    client_state::ClientState, consensus_state::ConsensusState, errors::Error,
    types::ConsensusUpdateInfo,
};
use ethereum_consensus::{
    beacon::Slot,
    compute::{compute_sync_committee_period_at_slot, compute_timestamp_at_slot},
    context::ChainContext,
    types::{H256, U64},
};
use ibc::timestamp::Timestamp;

pub fn apply_updates<const SYNC_COMMITTEE_SIZE: usize, C: ChainContext>(
    ctx: &C,
    client_state: &ClientState<SYNC_COMMITTEE_SIZE>,
    consensus_state: &ConsensusState,
    consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    block_number: U64,
    account_storage_root: H256,
    timestamp: Timestamp,
) -> Result<(ClientState<SYNC_COMMITTEE_SIZE>, ConsensusState), Error> {
    let store_period = consensus_state.current_period(ctx);
    let update_slot = consensus_update.finalized_header.0.slot;
    let update_period = compute_sync_committee_period_at_slot(ctx, update_slot);
    let timestamp = timestamp.into_tm_time().unwrap().unix_timestamp() as u64;
    let finalized_header_timestamp: u64 = compute_timestamp_at_slot(ctx, update_slot).into();
    if finalized_header_timestamp != timestamp {
        return Err(Error::UnexpectedTimestamp(
            finalized_header_timestamp,
            timestamp,
        ));
    }

    // We can assume that the update's finalized period is equal to the attested period by `LightClientStoreReader::ensure_relevant_update()`
    // The sync committee info is based on the attested period, so we can use the finalized period to determine the sync committee info.
    // Let `store_period` be the period of the current sync committe of the consensus state, then the state transition is the following:
    // - If `store_period == update_period`, then the new consensus state will have the same sync committee info as the current consensus state.
    // - If `store_period + 1 == update_period`, then the new consensus state will have the current sync committee as the next sync committee of the current consensus state,
    //   and the next sync committee of the new consensus state will be the next sync committee of the update.

    let new_consensus_state = if store_period == update_period {
        ConsensusState {
            slot: update_slot,
            storage_root: account_storage_root.0.to_vec().into(),
            timestamp: wrap_compute_timestamp_at_slot(ctx, update_slot)?,
            current_sync_committee: consensus_state.current_sync_committee.clone(),
            next_sync_committee: consensus_state.next_sync_committee.clone(),
        }
    } else if store_period + 1 == update_period {
        if let Some((update_next_sync_committee, _)) = consensus_update.next_sync_committee {
            ConsensusState {
                slot: update_slot,
                storage_root: account_storage_root.0.to_vec().into(),
                timestamp: wrap_compute_timestamp_at_slot(ctx, update_slot)?,
                current_sync_committee: consensus_state.next_sync_committee.clone(),
                next_sync_committee: update_next_sync_committee.aggregate_pubkey,
            }
        } else {
            // Relayers must submit an update that contains the next sync committee if the update period is `store_period + 1`.
            return Err(Error::NoNextSyncCommitteeInConsensusUpdate(
                store_period.into(),
                update_period.into(),
            ));
        }
    } else {
        // store_period + 1 < update_period
        // Relayers must submit an update that contains the next sync committee if the update period is `store_period + 1`` in advance.
        return Err(Error::FuturePeriodError(store_period, update_period));
    };

    let mut new_client_state = client_state.clone();
    if client_state.latest_slot < update_slot {
        new_client_state.latest_slot = update_slot;
    }
    if client_state.latest_execution_block_number < block_number {
        new_client_state.latest_execution_block_number = block_number;
    }
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
