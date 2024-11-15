# ethereum-ibc-rs

[![test](https://github.com/datachainlab/ethereum-ibc-rs/actions/workflows/test.yml/badge.svg)](https://github.com/datachainlab/ethereum-ibc-rs/actions/workflows/test.yml)

`ethereum-ibc-rs` is an implementation of a light client based on the sync protocol introduced with the Altair hard fork in the beacon chain (also called as the consensus layer). In addition to verifying beacon headers, it also supports verifying IBC commitments in [ibc-solidity](https://github.com/hyperledger-labs/yui-ibc-solidity) using the `state_root` of the finalized execution payload contained within the header.

## The sync protocol in the nutshell

The sync protocol is a protocol that enables efficient verification of the beacon chain using fewer resources than a full node, which is referred to as a light client.

A sync committee is a group of validators, chosen from the active validators of the beacon chain, for every 256 epochs (i.e., 1 period, approximately 27.3h). The sync committee continuously signs block headers for each slot of the beacon chain.

A beacon header signed by the sync committee is referred to as an attested header. We can consider a finalized header if it is based on a finalized checkpoint included in the state root of a valid attested header. Furthermore, a finalized header contains a `body_root`, which is the root of a tree constructed with the fields of the `BeaconBlockBody`. This `BeaconBlockBody` includes an `execution_payload`, so we can get a finalized execution payload by traversing a tree with valid attested header as root.

Additionally, the `state_root` of an attested header indicates the root of a tree constructed with the fields of the `BeaconState`. The `BeaconState` includes the public keys of the current and next sync committees based on the attested header's period. By tracking the committee information, which is updated per period, the light client can verify headers of next period.

For more details, refer to [this link](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md).

## Light Client Design

### Overview

Our light client verifies attestations of headers by the sync committee defined in the sync protocol. Note that our light client will only accept headers where there are sufficient attest stations. This means that it does not track `optimistic_header` in [the spec](https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/specs/altair/light-client/sync-protocol.md#lightclientstore). 

It also can verify commitments of the IBC contract by traversing a tree with the finalized header as root.

The light client implements the semantics and interfaces of [ICS-02](https://github.com/cosmos/ibc/tree/main/spec/core/ics-002-client-semantics).
The state consists of [`ClientState`](#state-definition), which includes parameters for verification, and [`ConsensusState`](#state-definition), which contains information based on verified finalized headers and the committee information for the corresponding period. Note that the "Height" in ICS-02 is represented as the block number of the execution layer, while the revision number is always set to 0.

Currently, the light client implementation suports forks bellatrix to electra.

### Trust Assumptions

Our light client protocol relies on the following trust assumptions:

- Supermajority (i.e., at least 2/3) of sync committee are honest.
- As liveness assumption, it is assumed that the beacon chain achieves finality in at least one epoch within each period. This is required to get at least one finalized next sync committee from the attested headers per period.

### Sync Process

Initially, the light client is set up by a relayer, which is a trustless component, using the `ClientState` and the `ConsensusState` corresponding to its `latest_execution_block_number`.

After initialization, the light client receives [`Header`](./proto/definitions/ibc/lightclients/ethereum/v1/ethereum.proto#L37)s from the relayer, verifies them, and updates its state. The relayer constructs the `Header` with [`LightClientUpdate`](https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/specs/altair/light-client/sync-protocol.md#lightclientupdate) and [`FinalityUpdate`](https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate) obtained from the beacon chain's RPC, along with height of the consensus state required to verify these [`Header.consensus_update`](./proto/definitions/ibc/lightclients/ethereum/v1/ethereum.proto#L77).

The header verification by the light client mainly involves the following steps:

- Retrieve the consensus state corresponding to `Header.trusted_sync_committee.height`.
- Confirm that the aggregated pubkey of `current_sync_committee` in the consensus state matches `Header.trusted_sync_committee.sync_committee`. Note that the consensus state maintains both current and next sync committee information, so it is necessary to check `Header.trusted_sync_committee.is_next` to determine which one it refers to.
- Ensure there are sufficient attestations by the sync committee corresponding to the `period` of `Header.consensus_update.signature_slot` for `Header.consensus_update.attested_header`.
- Verify each merkle branch contained in `Header.consensus_update` and [`Header.execution_update`](./proto/definitions/ibc/lightclients/ethereum/v1/ethereum.proto#L99). If the verification is successful, the finalized execution payload's `state_root` and `block_number` and `next_sync_committee`(if contained) can be obtained.
- Verify the account existence proof and account storage root from [`Header.account_update`](./proto/definitions/ibc/lightclients/ethereum/v1/ethereum.proto#L106) with the `state_root` as the root of MPT.

After the all verification process is successful, the light client constructs a new consensus state from the account's `storage_root`, `block_number` and current/next sync committee information and persists it in the store. These logic is implemented in [`check_header_and_update_state()`](./crates/ibc/src/client_state.rs#L349).

Typically, the relayer performs this process when it detects that unrelayed packets are contained in a block older than or equal to the latest finalized block number. However, if `calc_period_at_slot(latest ConsensusState.slot) + 1 < calc_period_at_slot(Header.consensus_update.signature_slot)` is true, it is necessary to persits `ConsensusState` containing committee information in advance using an intermediate period of `LightClientUpdate` to verify subsequent headers.

### State Verification

Based on the `storage_root` of the consensus state stored in the light client, it is possible to verify the membership of the commitments in the IBC contract. The `storage_root` represents the storage root of the IBC contract corresponding to the `ibc_address` of the client state. Therefore, based on the corresponding Merkle Patricia Tree, we can check the existence of commitments for each path defined in [IBCCommitment.sol](https://github.com/hyperledger-labs/yui-ibc-solidity/blob/0e83dc7aadf71380dae6e346492e148685510663/contracts/core/24-host/IBCCommitment.sol#L6).

### Misbehaviour Detection

Currently, the sync protocol does not define misbehavior for sync committee in the spec. In our light client, we define two types of misbehavior, [`FinalizedHeaderMisbehaviour`](./proto/definitions/ibc/lightclients/ethereum/v1/ethereum.proto#L119) and [`NextSyncCommitteeMisbehaviour`](./proto/definitions/ibc/lightclients/ethereum/v1/ethereum.proto#L126), following [the misbehaviour definition of ICS-02](https://github.com/cosmos/ibc/tree/47fea20d4d400e967721396092c6b43398c65d78/spec/core/ics-002-client-semantics#definitions).

If either type of misbehavior is detected, the light client sets the `frozenHeight` in the client state to the height of the consensus state referred to check the validity of the misbehavior.

- `FinalizedHeaderMisbehaviour` is defined as the existence of two valid `consensus_update` instances satisfying the following conditions: 
  1. Both updates are valid with the client's consensus state.  
  2. Each finalized header in the two updates corresponds to the same slot.  
  3. The two finalized headers are different from each other.

- `NextSyncCommitteeMisbehaviour` is defined as the existence of two valid `consensus_update` instances satisfying the following conditions:  
  1. Both updates are valid with the client's consensus state.  
  2. Each attested header in the two updates corresponds to the same period with a finalized next sync committee.  
  3. The two next sync committees differ from each other.

These logic is implemented in [`check_misbehaviour_and_update_state()`](./crates/ibc/src/client_state.rs#L432).

### State definition

#### ClientState

```proto
message ClientState {
  // `genesis_validators_root` of the target beacon chain's BeaconState
  bytes genesis_validators_root = 1;
  // https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/specs/altair/light-client/sync-protocol.md#misc
  uint64 min_sync_committee_participants = 2;
  // `genesis_time` of the target beacon chain's BeaconState
  uint64 genesis_time = 3;
  /// fork parameters of the target beacon chain
  ForkParameters fork_parameters = 4;
  // https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/configs/mainnet.yaml#L69
  uint64 seconds_per_slot = 5;
  // https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/presets/mainnet/phase0.yaml#L36
  uint64 slots_per_epoch = 6;
  // https://github.com/ethereum/consensus-specs/blob/a09d0c321550c5411557674a981e2b444a1178c0/presets/mainnet/altair.yaml#L18
  uint64 epochs_per_sync_committee_period = 7;
  // An address of IBC contract on execution layer
  bytes ibc_address = 8;
  // The IBC contract's base storage location for storing commitments
  // https://github.com/hyperledger-labs/yui-ibc-solidity/blob/0e83dc7aadf71380dae6e346492e148685510663/docs/architecture.md#L46
  bytes ibc_commitments_slot = 9;
  // `trust_level` is threshold of sync committee participants to consider the attestation as valid. Highly recommended to be 2/3.
  Fraction trust_level = 10;
  // `trusting_period` is the period in which the consensus state is considered trusted
  google.protobuf.Duration trusting_period = 11;
  // `max_clock_drift` defines how much new finalized header's time can drift into the future
  google.protobuf.Duration max_clock_drift = 12;
  // The latest block number of the stored consensus state
  uint64 latest_execution_block_number = 13;
  // `frozen_height` is the height at which the client is considered frozen. If `None`, the client is unfrozen.
  ibc.core.client.v1.Height frozen_height = 14;
}
```

#### ConsensusState

```proto
message ConsensusState {
  // finalized header's slot
  uint64 slot = 1;
  // the storage root of the IBC contract
  bytes storage_root = 2;
  // timestamp of finalized header
  google.protobuf.Timestamp timestamp = 3;
  // aggregate public key of current sync committee
  // "current" indicates a period corresponding to the `slot`
  bytes current_sync_committee = 4;
  // aggregate public key of next sync committee
  // "next" indicates `current + 1` period
  bytes next_sync_committee = 5;
}
```
