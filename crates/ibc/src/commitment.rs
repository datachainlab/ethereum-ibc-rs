use crate::errors::Error;
use crate::internal_prelude::*;
use ethereum_consensus::types::H256;
use ibc::core::ics24_host::Path;
use rlp::Rlp;
use tiny_keccak::{Hasher, Keccak};

/// Calculate the storage location for the commitment stored in the IBC contract
///
/// The spec is here: https://github.com/hyperledger-labs/yui-ibc-solidity/blob/0e83dc7aadf71380dae6e346492e148685510663/docs/architecture.md#L46
pub fn calculate_ibc_commitment_storage_location(ibc_commitments_slot: &H256, path: Path) -> H256 {
    keccak_256(
        &[
            &keccak_256(&path.into_bytes()),
            ibc_commitments_slot.as_bytes(),
        ]
        .concat(),
    )
    .into()
}

/// decode rlp format `List<List>` to `Vec<List>`
pub fn decode_eip1184_rlp_proof(proof: Vec<u8>) -> Result<Vec<Vec<u8>>, Error> {
    let r = Rlp::new(&proof);
    if r.is_list() {
        Ok(r.into_iter()
            .map(|r| {
                let proof: Vec<Vec<u8>> = r.as_list().unwrap();
                rlp::encode_list::<Vec<u8>, Vec<u8>>(&proof).into()
            })
            .collect())
    } else {
        Err(Error::InvalidProofFormatError(
            "proof must be rlp list".into(),
        ))
    }
}

fn keccak_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(input);
    k.finalize(&mut out);
    out
}
