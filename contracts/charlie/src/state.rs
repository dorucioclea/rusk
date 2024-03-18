// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use dusk_bytes::Serializable;
use dusk_pki::{PublicKey, PublicSpendKey};
use rusk_abi::TRANSFER_CONTRACT;
use stake_contract_types::*;
use transfer_contract_types::Stct;

#[derive(Debug, Clone)]
pub struct Charlie;

impl Charlie {
    pub fn ping(&mut self) {
        rusk_abi::debug!("Charlie ping - Charlie is a sponsor");
    }

    /// loads the contract with funds which can be used
    /// to sponsor free uses of some methods of this contract
    /// technically, the funds passed in this call will be used
    /// when granting allowances
    /// this operation is similar to staking, but the funds
    /// are staked into this contract's "wallet" rather than
    /// into the stake contract's wallet
    pub fn subsidize(&mut self, stake: Stake) {
        // verify the signature is over the correct digest
        // note: counter is always zero - make sure that this is safe
        let digest = stake_signature_message(0, stake.value).to_vec();

        if !rusk_abi::verify_bls(digest, stake.public_key, stake.signature) {
            panic!("Invalid signature!");
        }

        // make call to transfer contract to transfer balance from the user to
        // this contract
        let transfer_module = TRANSFER_CONTRACT;

        let stct = Stct {
            module: rusk_abi::self_id().to_bytes(),
            value: stake.value,
            proof: stake.proof,
        };

        rusk_abi::debug!(
            "charlie - subsidize - subsidize contract {:x?} with value {}",
            stct.module,
            stct.value
        );

        let r: bool = rusk_abi::call(transfer_module, "stct", &stct)
            .expect("Sending note to contract should succeed");

        rusk_abi::debug!(
            "charlie - subsidize - called stct and it returned {}",
            r
        );
    }

    /// at the moment it does not need to be mutable on self,
    /// but it will be as there is a need to store information
    /// about allowances given out to respective beneficiaries
    /// hence we need to keep &mut self here
    pub fn get_allowance(
        &mut self,
        _hint: Vec<u64>,
        _beneficiary_pk: PublicKey,
    ) -> (u64, [u8; PublicSpendKey::SIZE]) {
        const DEFAULT_ALLOWANCE: u64 = 10_000_000_000;
        let allowance = DEFAULT_ALLOWANCE;
        // here:
        // use the given hint and beneficiary pk to
        // determine the allowance
        // allowance can be zero if the given pk indicates user which
        // this sponsor contract does not want to fund
        // in any case the sponsor contract should return its own
        // psk to obtain a change from the allowance given
        // i.e., the not spent (unused) part of the allowance
        (allowance, rusk_abi::self_owner())
    }
}
