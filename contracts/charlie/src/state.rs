// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use dusk_bytes::Serializable;
use dusk_pki::{PublicKey, PublicSpendKey};

#[derive(Debug, Clone)]
pub struct Charlie;

impl Charlie {
    pub fn ping(&mut self) {
        rusk_abi::debug!("Charlie ping - Charlie is a sponsor");
    }

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
