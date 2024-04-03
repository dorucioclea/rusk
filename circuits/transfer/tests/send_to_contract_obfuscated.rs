// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use transfer_circuits::{
    DeriveKey, SendToContractObfuscatedCircuit, StcoCrossover, StcoMessage,
};

use ff::Field;
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use dusk_plonk::prelude::*;
use phoenix_core::{Message, Note, PublicKey, SecretKey};

mod keys;
use keys::load_keys;

fn create_random_circuit<R: RngCore + CryptoRng>(
    rng: &mut R,
    public_derive_key: bool,
) -> SendToContractObfuscatedCircuit {
    let c_sk = SecretKey::random(rng);
    let c_pk = PublicKey::from(c_sk);

    let value = rng.gen();

    let c_blinder = JubJubScalar::random(&mut *rng);
    let c_note = Note::obfuscated(rng, &c_pk, value, c_blinder);

    let (mut fee, crossover) = c_note
        .try_into()
        .expect("Failed to convert note into fee/crossover pair!");

    fee.gas_limit = 5;
    fee.gas_price = 1;

    let m_sk = SecretKey::random(rng);
    let m_pk = PublicKey::from(m_sk);

    let r = JubJubScalar::random(&mut *rng);
    let message = Message::new(rng, &r, &m_pk, value);

    let address = BlsScalar::random(&mut *rng);
    let signature = SendToContractObfuscatedCircuit::sign(
        rng, &c_sk, &fee, &crossover, &message, &address,
    );

    let message = {
        let (_, blinder) = message
            .decrypt(&r, &m_pk)
            .expect("Failed to decrypt message");
        let derive_key = DeriveKey::new(public_derive_key, &m_pk);
        let pk_r = *m_pk.gen_stealth_address(&r).pk_r().as_ref();
        StcoMessage {
            blinder,
            derive_key,
            message,
            pk_r,
            r,
        }
    };

    let crossover = StcoCrossover::new(crossover, c_blinder);

    SendToContractObfuscatedCircuit::new(
        value, message, crossover, &fee, address, signature,
    )
}

#[test]
fn send_to_contract_obfuscated_public_key() {
    let rng = &mut StdRng::seed_from_u64(2322u64);

    let (prover, verifier) = load_keys("SendToContractObfuscatedCircuit")
        .expect("Keys should be stored");

    let circuit = create_random_circuit(rng, true);

    let (proof, public_inputs) = prover
        .prove(rng, &circuit)
        .expect("Proving the circuit should be successful");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verifying the circuit should succeed");
}

#[test]
fn send_to_contract_obfuscated_secret_key() {
    let rng = &mut StdRng::seed_from_u64(2322u64);

    let (prover, verifier) = load_keys("SendToContractObfuscatedCircuit")
        .expect("Keys should be stored");

    let circuit = create_random_circuit(rng, false);

    let (proof, public_inputs) = prover
        .prove(rng, &circuit)
        .expect("Proving the circuit should be successful");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verifying the circuit should succeed");
}
