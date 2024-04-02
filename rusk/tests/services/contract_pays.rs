// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use dusk_wallet_core::{self as wallet};
use rand::prelude::*;
use rand::rngs::StdRng;
use rusk::{Result, Rusk};
use rusk_abi::ContractId;
use tempfile::tempdir;
use tracing::info;
use rusk_recovery_tools::state;

use crate::common::logger;
use crate::common::state::{generator_procedure, ExecuteResult};
use crate::common::wallet::{TestProverClient, TestStateClient, TestStore};

const BLOCK_HEIGHT: u64 = 1;
const BLOCK_GAS_LIMIT: u64 = 1_000_000_000_000;
const INITIAL_BALANCE: u64 = 10_000_000_000;

const GAS_LIMIT_0: u64 = 1_000; // Not enough to spend
const GAS_LIMIT_1: u64 = 200_000_000; // All ok

const CHARLIE_CONTRACT_ID: ContractId = {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xFC;
    ContractId::from_bytes(bytes)
};

fn initial_state<P: AsRef<Path>>(dir: P) -> Result<Rusk> {
    let snapshot = toml::from_str(include_str!("../config/contract_pays.toml"))
        .expect("Cannot deserialize config");

    let dir = dir.as_ref();

    let (_vm, _commit_id) = state::deploy2(dir, &snapshot)
        .expect("Deploying initial state should succeed");

    let rusk = Rusk::new(dir).expect("Instantiating rusk should succeed");
    Ok(rusk)
}


const SENDER_INDEX_0: u64 = 0;
const SENDER_INDEX_1: u64 = 1;

fn make_transactions(
    rusk: &Rusk,
    wallet: &wallet::Wallet<TestStore, TestStateClient, TestProverClient>,
) {
    // We will refund the transaction to ourselves.
    let refund_0 = wallet
        .public_spend_key(SENDER_INDEX_0)
        .expect("Getting a public spend key should succeed");

    let initial_balance_0 = wallet
        .get_balance(SENDER_INDEX_0)
        .expect("Getting initial balance should succeed")
        .value;

    // We will refund the transaction to ourselves.
    let refund_1 = wallet
        .public_spend_key(SENDER_INDEX_1)
        .expect("Getting a public spend key should succeed");

    let initial_balance_1 = wallet
        .get_balance(SENDER_INDEX_1)
        .expect("Getting initial balance should succeed")
        .value;

    assert_eq!(
        initial_balance_0, INITIAL_BALANCE,
        "The sender should have the given initial balance"
    );

    assert_eq!(
        initial_balance_1, INITIAL_BALANCE,
        "The sender should have the given initial balance"
    );

    let mut rng = StdRng::seed_from_u64(0xdead);

    // First transaction will also be a `wallet.execute` to the charlie
    // contract, but with no enough gas to spend. Transaction should be
    // discarded
    let tx_0 = wallet
        .execute(
            &mut rng,
            CHARLIE_CONTRACT_ID.to_bytes().into(),
            String::from("ping"),
            (),
            SENDER_INDEX_0,
            &refund_0,
            GAS_LIMIT_0,
            1,
        )
        .expect("Making the transaction should succeed");

    // Second transaction transaction will also be a `wallet.execute` to the
    // charlie contract. This transaction will be tested for gas cost.
    let tx_1 = wallet
        .execute(
            &mut rng,
            CHARLIE_CONTRACT_ID.to_bytes().into(),
            String::from("ping"),
            (),
            SENDER_INDEX_1,
            &refund_1,
            GAS_LIMIT_1,
            1,
        )
        .expect("Making the transaction should succeed");

    let expected = ExecuteResult {
        discarded: 1,
        executed: 1,
    };

    let spent_transactions = generator_procedure(
        rusk,
        &[tx_0, tx_1],
        BLOCK_HEIGHT,
        BLOCK_GAS_LIMIT,
        vec![],
        Some(expected),
    )
    .expect("generator procedure should succeed");

    let mut spent_transactions = spent_transactions.into_iter();
    let tx = spent_transactions
        .next()
        .expect("There should be one spent transactions");

    assert!(tx.err.is_none(), "The second transaction should succeed");
    println!("tx gas spent={}", tx.gas_spent);
    assert!(
        tx.gas_spent < GAS_LIMIT_1,
        "Successful transaction should consume less than provided"
    );
}

#[tokio::test(flavor = "multi_thread")]
pub async fn contract_pays() -> Result<()> {
    // Setup the logger
    logger();

    let tmp = tempdir().expect("Should be able to create temporary directory");
    let rusk = initial_state(&tmp)?;

    let cache = Arc::new(RwLock::new(HashMap::new()));

    // Create a wallet
    let wallet = wallet::Wallet::new(
        TestStore,
        TestStateClient {
            rusk: rusk.clone(),
            cache,
        },
        TestProverClient::default(),
    );

    let original_root = rusk.state_root();

    info!("Original Root: {:?}", hex::encode(original_root));

    make_transactions(&rusk, &wallet);

    // Check the state's root is changed from the original one
    let new_root = rusk.state_root();
    info!(
        "New root after the 1st transfer: {:?}",
        hex::encode(new_root)
    );
    assert_ne!(original_root, new_root, "Root should have changed");

    Ok(())
}
