use crate::{
    client_state::ClientState, consensus_state::ConsensusState, errors::Error,
    types::ConsensusUpdateInfo,
};
use ethereum_consensus::{
    compute::compute_sync_committee_period_at_slot,
    context::ChainContext,
    types::{H256, U64},
};
use ibc::timestamp::Timestamp;

/// Apply the verified updates to the state and return the new state.
///
/// CONTRACT: `apply_updates` must be called after `SyncProtocolVerifier::validate_updates()`
/// The `update` satisfies the following conditions:
/// - finalized_period <= attested_period <= signature_period
/// - `consensus_update`'s signature period in (store_period, store_period + 1) == True
pub fn apply_updates<const SYNC_COMMITTEE_SIZE: usize, C: ChainContext>(
    ctx: &C,
    client_state: &ClientState<SYNC_COMMITTEE_SIZE>,
    consensus_state: &ConsensusState,
    consensus_update: ConsensusUpdateInfo<SYNC_COMMITTEE_SIZE>,
    block_number: U64,
    account_storage_root: H256,
    header_timestamp: Timestamp,
) -> Result<(ClientState<SYNC_COMMITTEE_SIZE>, ConsensusState), Error> {
    let store_period = consensus_state.current_period(ctx);
    let update_finalized_slot = consensus_update.finalized_header.0.slot;
    let update_finalized_period = compute_sync_committee_period_at_slot(ctx, update_finalized_slot);

    // Let `store_period` be the period of the current sync committe of the consensus state, then the state transition is the following:
    // - If `store_period == update_finalized_period`, then the new consensus state will have the same sync committee info as the current consensus state.
    // - If `store_period + 1 == update_finalized_period`, then the new consensus state will have the current sync committee as the next sync committee of the current consensus state,
    //   and the next sync committee of the new consensus state will be the next sync committee of the update.
    let new_consensus_state = if store_period == update_finalized_period {
        // store_period == finalized_period <= attested_period <= signature_period
        ConsensusState {
            slot: update_finalized_slot,
            storage_root: account_storage_root.0.to_vec().into(),
            timestamp: header_timestamp,
            current_sync_committee: consensus_state.current_sync_committee.clone(),
            next_sync_committee: consensus_state.next_sync_committee.clone(),
        }
    } else if store_period + 1 == update_finalized_period {
        // store_period + 1 == finalized_period == attested_period == signature_period
        // Why `finalized_period == attested_period == signature_period` here?
        // Because our store only have the current or next sync committee info, so the verified update's signature period must match the `store_period + 1` here.
        if let Some((update_next_sync_committee, _)) = consensus_update.next_sync_committee {
            ConsensusState {
                slot: update_finalized_slot,
                storage_root: account_storage_root.0.to_vec().into(),
                timestamp: header_timestamp,
                current_sync_committee: consensus_state.next_sync_committee.clone(),
                next_sync_committee: update_next_sync_committee.aggregate_pubkey,
            }
        } else {
            // Relayers must submit an update that contains the next sync committee if the update period is `store_period + 1`.
            return Err(Error::NoNextSyncCommitteeInConsensusUpdate(
                store_period,
                update_finalized_period,
            ));
        }
    } else {
        // store_period + 1 < update_finalized_period or store_period > update_finalized_period
        // The store(=consensus state) cannot apply such updates here because the current or next sync committee corresponding to the `finalized_period` is unknown.
        return Err(Error::StoreNotSupportedFinalizedPeriod(
            store_period,
            update_finalized_period,
        ));
    };

    let mut new_client_state = client_state.clone();
    if client_state.latest_execution_block_number < block_number {
        new_client_state.latest_execution_block_number = block_number;
    }
    new_client_state.validate()?;
    new_consensus_state.validate()?;
    Ok((new_client_state, new_consensus_state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use ethereum_consensus::beacon::Version;
    use ethereum_consensus::compute::compute_timestamp_at_slot;
    use ethereum_consensus::context::ChainContext;
    use ethereum_consensus::fork::altair::ALTAIR_FORK_SPEC;
    use ethereum_consensus::fork::bellatrix::BELLATRIX_FORK_SPEC;
    use ethereum_consensus::fork::capella::CAPELLA_FORK_SPEC;
    use ethereum_consensus::fork::deneb::DENEB_FORK_SPEC;
    use ethereum_consensus::fork::{ForkParameter, ForkParameters};
    use ethereum_consensus::preset::minimal::PRESET;
    use ethereum_consensus::types::Address;
    use ethereum_consensus::{config, types::U64};
    use ethereum_light_client_verifier::updates::ConsensusUpdate;
    use ethereum_light_client_verifier::{
        consensus::test_utils::{gen_light_client_update_with_params, MockSyncCommitteeManager},
        context::{Fraction, LightClientContext},
        updates::ConsensusUpdateInfo as EthConsensusUpdateInfo,
    };
    use hex_literal::hex;
    use ibc::core::ics23_commitment::commitment::CommitmentRoot;
    use std::time::SystemTime;

    #[test]
    pub fn test_apply_updates() {
        let scm = MockSyncCommitteeManager::<32>::new(1, 6);
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

        let slots_per_period = ctx.slots_per_epoch() * ctx.epochs_per_sync_committee_period();
        let base_store_period = 3u64;
        let base_store_slot = U64(base_store_period) * slots_per_period;
        let base_finalized_epoch = base_store_slot / ctx.slots_per_epoch() + 1;
        let base_attested_slot = (base_finalized_epoch + 2) * ctx.slots_per_epoch();
        let base_signature_slot = base_attested_slot + 1;

        let current_sync_committee = scm.get_committee(base_store_period);
        let dummy_execution_state_root = [1u8; 32].into();
        let dummy_execution_block_number = 1;

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

        let consensus_state = ConsensusState {
            slot: base_store_slot,
            storage_root: CommitmentRoot::from_bytes(keccak256("storage_root").as_bytes()),
            timestamp: Timestamp::from_nanoseconds(
                compute_timestamp_at_slot(&ctx, base_store_slot).0 * 1_000_000_000,
            )
            .unwrap(),
            current_sync_committee: scm
                .get_committee(base_store_period)
                .to_committee()
                .aggregate_pubkey,
            next_sync_committee: scm
                .get_committee(base_store_period + 1)
                .to_committee()
                .aggregate_pubkey,
        };

        {
            // store_period == finalized_period == attested_period == signature_period
            let update = to_consensus_update_info(gen_light_client_update_with_params::<32, _>(
                &ctx,
                base_signature_slot,
                base_attested_slot,
                base_finalized_epoch,
                dummy_execution_state_root,
                dummy_execution_block_number.into(),
                current_sync_committee,
                scm.get_committee(base_store_period + 1),
                true,
                32,
            ));
            let new_block_number = 2.into();
            let res = apply_updates(
                &ctx,
                &client_state,
                &consensus_state,
                update.clone(),
                new_block_number,
                H256::from_slice(&[1u8; 32]),
                Timestamp::from_nanoseconds(
                    compute_timestamp_at_slot(&ctx, update.finalized_header.0.slot).0
                        * 1_000_000_000,
                )
                .unwrap(),
            );
            assert!(res.is_ok(), "{:?}", res);
            let (new_client_state, new_consensus_state) = res.unwrap();
            assert_eq!(
                new_client_state.latest_execution_block_number,
                new_block_number
            );
            assert_eq!(new_consensus_state.slot, update.finalized_header.0.slot);
            // sync committee info should be the same as the current consensus state
            assert_eq!(
                new_consensus_state.current_sync_committee,
                scm.get_committee(base_store_period)
                    .to_committee()
                    .aggregate_pubkey
            );
            assert_eq!(
                new_consensus_state.next_sync_committee,
                scm.get_committee(base_store_period + 1)
                    .to_committee()
                    .aggregate_pubkey
            );
        }
        {
            // store_period + 1 == finalized_period == attested_period == signature_period
            let update = to_consensus_update_info(gen_light_client_update_with_params::<32, _>(
                &ctx,
                base_signature_slot + slots_per_period,
                base_attested_slot + slots_per_period,
                base_finalized_epoch + ctx.epochs_per_sync_committee_period(),
                dummy_execution_state_root,
                dummy_execution_block_number.into(),
                current_sync_committee,
                scm.get_committee(base_store_period + 2),
                true,
                32,
            ));
            let new_block_number = 2.into();
            let res = apply_updates(
                &ctx,
                &client_state,
                &consensus_state,
                update.clone(),
                new_block_number,
                H256::from_slice(&[1u8; 32]),
                Timestamp::from_nanoseconds(
                    compute_timestamp_at_slot(&ctx, update.finalized_header.0.slot).0
                        * 1_000_000_000,
                )
                .unwrap(),
            );
            assert!(res.is_ok(), "{:?}", res);
            let (new_client_state, new_consensus_state) = res.unwrap();
            assert_eq!(
                new_client_state.latest_execution_block_number,
                new_block_number
            );
            assert_eq!(new_consensus_state.slot, update.finalized_header.0.slot);
            // sync committee info should be the same as the current consensus state
            assert_eq!(
                new_consensus_state.current_sync_committee,
                scm.get_committee(base_store_period + 1)
                    .to_committee()
                    .aggregate_pubkey
            );
            assert_eq!(
                new_consensus_state.next_sync_committee,
                scm.get_committee(base_store_period + 2)
                    .to_committee()
                    .aggregate_pubkey
            );
        }
        {
            // store_period + 1 == finalized_period == attested_period == signature_period
            // but the update has no next sync committee
            let update = to_consensus_update_info(gen_light_client_update_with_params::<32, _>(
                &ctx,
                base_signature_slot + slots_per_period,
                base_attested_slot + slots_per_period,
                base_finalized_epoch + ctx.epochs_per_sync_committee_period(),
                dummy_execution_state_root,
                dummy_execution_block_number.into(),
                current_sync_committee,
                scm.get_committee(base_store_period + 2),
                false,
                32,
            ));
            let new_block_number = 2.into();
            let res = apply_updates(
                &ctx,
                &client_state,
                &consensus_state,
                update.clone(),
                new_block_number,
                H256::from_slice(&[1u8; 32]),
                Timestamp::from_nanoseconds(
                    compute_timestamp_at_slot(&ctx, update.finalized_header.0.slot).0
                        * 1_000_000_000,
                )
                .unwrap(),
            );
            assert!(res.is_err(), "{:?}", res);
            if let Err(Error::NoNextSyncCommitteeInConsensusUpdate(store_period, update_period)) =
                res
            {
                assert_eq!(store_period.0, base_store_period);
                assert_eq!(update_period.0, base_store_period + 1);
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }
        {
            // finalized_period - 1 == store_period == attested_period == signature_period
            let update = to_consensus_update_info(gen_light_client_update_with_params::<32, _>(
                &ctx,
                base_signature_slot,
                base_attested_slot,
                base_finalized_epoch - ctx.epochs_per_sync_committee_period(),
                dummy_execution_state_root,
                dummy_execution_block_number.into(),
                current_sync_committee,
                scm.get_committee(base_store_period),
                true,
                32,
            ));
            let new_block_number = 2.into();
            let res = apply_updates(
                &ctx,
                &client_state,
                &consensus_state,
                update.clone(),
                new_block_number,
                H256::from_slice(&[1u8; 32]),
                Timestamp::from_nanoseconds(
                    compute_timestamp_at_slot(&ctx, update.finalized_header.0.slot).0
                        * 1_000_000_000,
                )
                .unwrap(),
            );
            if let Err(Error::StoreNotSupportedFinalizedPeriod(store_period, update_period)) = res {
                assert_eq!(store_period.0, base_store_period);
                assert_eq!(
                    update_period,
                    compute_sync_committee_period_at_slot(
                        &ctx,
                        update.finalized_beacon_header().slot
                    )
                );
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }
    }

    fn keccak256(s: &str) -> H256 {
        use tiny_keccak::{Hasher, Keccak};
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(s.as_bytes());
        hasher.finalize(&mut output);
        H256::from_slice(&output)
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
