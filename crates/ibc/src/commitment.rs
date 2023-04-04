use crate::errors::Error;
use crate::internal_prelude::*;
use ethereum_consensus::types::{Address, H256};
use ibc::core::ics24_host::Path;
use rlp::Rlp;
use tiny_keccak::{Hasher, Keccak};

pub fn calculate_account_path(ibc_address: &Address) -> H256 {
    keccak_256(&ibc_address.0).into()
}

pub fn calculate_ibc_commitment_storage_key(ibc_commitments_slot: &H256, path: Path) -> H256 {
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

pub fn extract_storage_root_from_account(account_rlp: &[u8]) -> Result<H256, Error> {
    let r = Rlp::new(account_rlp);
    if !r.is_list() {
        let items: Vec<Vec<u8>> = r.as_list()?;
        if items.len() != 4 {
            Err(Error::InvalidProofFormatError(
                "proof must be rlp list".into(),
            ))
        } else {
            Ok(H256::from_slice(items.get(2).unwrap()))
        }
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
