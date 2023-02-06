// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use transfer_circuits::{SendToContractTransparentCircuit, TRANSCRIPT_LABEL};

use dusk_pki::SecretSpendKey;
use phoenix_core::Note;
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};

use dusk_plonk::prelude::*;

mod keys;

fn create_random_circuit<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> SendToContractTransparentCircuit {
    let address = BlsScalar::random(rng);
    let value = rng.next_u64();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_spend_key();
    let blinder = JubJubScalar::random(rng);

    let note = Note::obfuscated(rng, &psk, value, blinder);
    let (mut fee, crossover) = note
        .try_into()
        .expect("Failed to convert note into fee/crossover pair!");

    fee.gas_limit = rng.next_u64();
    fee.gas_price = rng.next_u64();

    let signature = SendToContractTransparentCircuit::sign(
        rng, &ssk, &fee, &crossover, value, &address,
    );

    SendToContractTransparentCircuit::new(
        &fee, &crossover, value, blinder, address, signature,
    )
}

#[test]
fn send_to_contract_transparent() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let (pp, pk, vd) = keys::circuit_keys::<SendToContractTransparentCircuit>()
        .expect("Failed to generate circuit!");

    let mut circuit = create_random_circuit(rng);

    let proof = circuit
        .prove(&pp, &pk, TRANSCRIPT_LABEL)
        .expect("Failed to prove circuit");
    let pi = circuit.public_inputs();

    SendToContractTransparentCircuit::verify(
        &pp,
        &vd,
        &proof,
        pi.as_slice(),
        TRANSCRIPT_LABEL,
    )
    .expect("Failed to verify");
}