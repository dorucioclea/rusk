// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commons::{spawn_send_reduction, ConsensusError};
use crate::config;
use crate::contract_state::Operations;
use crate::execution_ctx::ExecutionCtx;
use crate::secondstep::handler;
use crate::user::committee::Committee;
use node_data::ledger::{to_str, Block};
use node_data::message::{Message, Payload};
use std::sync::Arc;
use tokio::sync::Mutex;

#[allow(unused)]
pub struct Reduction<T> {
    handler: handler::Reduction,
    candidate: Option<Block>,
    timeout_millis: u64,
    executor: Arc<Mutex<T>>,
}

impl<T: Operations + 'static> Reduction<T> {
    pub fn new(executor: Arc<Mutex<T>>) -> Self {
        Self {
            handler: handler::Reduction {
                aggr: Default::default(),
                first_step_votes: Default::default(),
            },
            candidate: None,
            timeout_millis: config::CONSENSUS_TIMEOUT_MS,
            executor,
        }
    }

    pub fn reinitialize(&mut self, msg: &Message, round: u64, step: u8) {
        self.candidate = None;
        self.handler.reset();

        if let Payload::StepVotesWithCandidate(p) = msg.payload.clone() {
            self.handler.first_step_votes = p.sv;
            self.candidate = Some(p.candidate);
        }

        tracing::debug!(
            event = "init",
            name = self.name(),
            round = round,
            step = step,
            timeout = self.timeout_millis,
            hash = to_str(
                &self
                    .candidate
                    .as_ref()
                    .map_or(&Block::default(), |c| c)
                    .header
                    .hash
            ),
            fsv_bitset = self.handler.first_step_votes.bitset,
        )
    }

    pub async fn run(
        &mut self,
        mut ctx: ExecutionCtx<'_>,
        committee: Committee,
    ) -> Result<Message, ConsensusError> {
        if committee.am_member() {
            //  Send reduction in async way
            if let Some(b) = &self.candidate {
                spawn_send_reduction(
                    &mut ctx.iter_ctx.join_set,
                    ctx.iter_ctx.verified_hash.clone(),
                    b.clone(),
                    committee.get_my_pubkey().clone(),
                    ctx.round_update.clone(),
                    ctx.step,
                    ctx.outbound.clone(),
                    ctx.inbound.clone(),
                    self.executor.clone(),
                );
            }
        }

        // handle queued messages for current round and step.
        if let Some(m) =
            ctx.handle_future_msgs(&committee, &mut self.handler).await
        {
            return Ok(m);
        }

        ctx.event_loop(&committee, &mut self.handler, &mut self.timeout_millis)
            .await
    }

    pub fn name(&self) -> &'static str {
        "2nd_red"
    }
    pub fn get_timeout(&self) -> u64 {
        self.timeout_millis
    }

    pub fn get_committee_size(&self) -> usize {
        config::SECOND_REDUCTION_COMMITTEE_SIZE
    }
}
