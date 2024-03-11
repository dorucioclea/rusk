// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use phoenix_core::transaction::*;
use rusk_abi::TRANSFER_CONTRACT;

/// Alice contract.
#[derive(Debug, Clone)]
pub struct Charlie;

impl Charlie {
    pub fn ping(&mut self) {
        rusk_abi::debug!("CHARLIE ping");
    }

    pub fn prepay(&mut self, value: u64, proof: Vec<u8>) {
        let stct = Stct {
            module: rusk_abi::self_id().to_bytes(),
            value,
            proof,
        };

        let _: bool = rusk_abi::call(TRANSFER_CONTRACT, "stct", &stct)
            .expect("Sending note to contract should succeed");
    }
}
