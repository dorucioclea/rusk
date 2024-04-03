// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use transfer_circuits::{
    DeriveKey, WfoChange, WfoCommitment, WithdrawFromObfuscatedCircuit,
};

use ff::Field;
use phoenix_core::{Message, Note, PublicKey, SecretKey};
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};

use dusk_plonk::prelude::*;

mod keys;
use keys::load_keys;

fn create_random_circuit<R: RngCore + CryptoRng>(
    rng: &mut R,
    public_derive_key: bool,
) -> WithdrawFromObfuscatedCircuit {
    let input = {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(sk);

        let value = 100;
        let r = JubJubScalar::random(&mut *rng);
        let message = Message::new(rng, &r, &pk, value);

        let (_, blinder) =
            message.decrypt(&r, &pk).expect("Failed to decrypt message");
        let commitment = *message.value_commitment();
        WfoCommitment {
            blinder,
            commitment,
            value,
        }
    };
    let change = {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(sk);

        let value = 25;
        let r = JubJubScalar::random(&mut *rng);
        let message = Message::new(rng, &r, &pk, value);
        let pk_r = *pk.gen_stealth_address(&r).pk_r().as_ref();

        let (_, blinder) =
            message.decrypt(&r, &pk).expect("Failed to decrypt message");

        let derive_key = DeriveKey::new(public_derive_key, &pk);
        WfoChange {
            blinder,
            derive_key,
            message,
            pk_r,
            r,
            value,
        }
    };

    let output = {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(sk);

        let value = 75;

        let blinder = JubJubScalar::random(&mut *rng);
        let output = Note::obfuscated(rng, &pk, value, blinder);
        let commitment = *output.value_commitment();
        WfoCommitment {
            blinder,
            commitment,
            value,
        }
    };

    WithdrawFromObfuscatedCircuit {
        input,
        change,
        output,
    }
}

#[test]
fn withdraw_from_obfuscated_public() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let (prover, verifier) = load_keys("WithdrawFromObfuscatedCircuit")
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
fn withdraw_from_obfuscated_private() {
    let rng = &mut StdRng::seed_from_u64(8586);

    let (prover, verifier) = load_keys("WithdrawFromObfuscatedCircuit")
        .expect("Keys should be stored");

    let circuit = create_random_circuit(rng, false);

    let (proof, public_inputs) = prover
        .prove(rng, &circuit)
        .expect("Proving the circuit should be successful");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verifying the circuit should succeed");
}
