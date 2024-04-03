// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use jubjub_schnorr::{
    SecretKey as NoteSecretKey, SignatureDouble as SchnorrSignature,
};
use phoenix_core::{Note, Ownable, SecretKey};
use rand_core::{CryptoRng, RngCore};

use dusk_plonk::prelude::*;

#[derive(Debug, Clone, Default)]
pub struct CircuitInputSignature {
    u: JubJubScalar,
    r: JubJubAffine,
    r_p: JubJubAffine,
}

impl From<SchnorrSignature> for CircuitInputSignature {
    fn from(sig: SchnorrSignature) -> Self {
        Self::from(&sig)
    }
}

impl From<&SchnorrSignature> for CircuitInputSignature {
    fn from(sig: &SchnorrSignature) -> Self {
        let u = *sig.u();
        let r = sig.R().into();
        let r_p = sig.R_prime().into();

        Self { u, r, r_p }
    }
}

impl CircuitInputSignature {
    pub const fn new(
        u: JubJubScalar,
        r: JubJubAffine,
        r_p: JubJubAffine,
    ) -> Self {
        Self { u, r, r_p }
    }

    pub fn sign<R: RngCore + CryptoRng>(
        rng: &mut R,
        sk: &SecretKey,
        note: &Note,
        tx_hash: BlsScalar,
    ) -> Self {
        let sk_r = *sk.sk_r(note.stealth_address()).as_ref();
        let sk_r = NoteSecretKey::from(&sk_r);

        let sig = sk_r.sign_double(rng, tx_hash);

        Self::from(sig)
    }

    pub const fn u(&self) -> &JubJubScalar {
        &self.u
    }

    pub const fn r(&self) -> &JubJubAffine {
        &self.r
    }

    pub const fn r_p(&self) -> &JubJubAffine {
        &self.r_p
    }

    pub const fn into_inner(
        self,
    ) -> (JubJubScalar, JubJubAffine, JubJubAffine) {
        (self.u, self.r, self.r_p)
    }
}
