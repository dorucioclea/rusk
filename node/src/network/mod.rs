// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::net::IpAddr;
use std::sync::Arc;
use std::{any, default};

use crate::{BoxedFilter, Message};
use async_trait::async_trait;
use kadcast::config::Config;
use kadcast::{MessageInfo, Peer};
use node_data::message::AsyncQueue;
use node_data::message::Metadata;
use tokio::sync::RwLock;

mod frame;

type RoutesList<const N: usize> = [Option<AsyncQueue<Message>>; N];
type FilterList<const N: usize> = [Option<BoxedFilter>; N];

pub struct Listener<const N: usize> {
    routes: Arc<RwLock<RoutesList<N>>>,
    filters: Arc<RwLock<FilterList<N>>>,
}

impl<const N: usize> Listener<N> {
    fn reroute(
        &self,
        topic: impl Into<u8>,
        msg: Message,
    ) -> anyhow::Result<()> {
        let topic = topic.into() as usize;

        _ = match self.routes.try_read()?.get(topic) {
            Some(Some(r)) => r.try_send(msg),
            _ => Ok(()),
        };

        Ok(())
    }

    fn call_filters(
        &self,
        topic: impl Into<u8>,
        msg: &Message,
    ) -> anyhow::Result<()> {
        let topic = topic.into() as usize;

        match self.filters.try_write()?.get_mut(topic) {
            Some(Some(f)) => f.filter(msg),
            _ => Ok(()),
        }
    }
}

impl<const N: usize> kadcast::NetworkListen for Listener<N> {
    fn on_message(&self, blob: Vec<u8>, md: MessageInfo) {
        match frame::PDU::decode(&mut &blob.to_vec()[..]) {
            Ok(d) => {
                let mut msg = d.payload;

                // Update Transport Data
                msg.metadata = Some(Metadata {
                    height: md.height(),
                    src_addr: md.src().to_string(),
                });

                // Allow upper layers to fast-discard a message before queueing
                if let Err(e) = self.call_filters(0, &msg) {
                    tracing::info!("discard message due to {:?}", e);
                    return;
                }

                // Reroute message to the upper layer
                if let Err(e) = self.reroute(0, msg) {
                    tracing::error!("could not reroute due to {:?}", e);
                }
            }
            Err(err) => {
                // Dump message blob and topic number
                let topic_pos = 8 + 8 + 8 + 4;

                tracing::error!(
                    "err: {:?}, msg_topic: {:?} msg_blob: {:?}",
                    err,
                    blob.get(topic_pos),
                    blob
                );
            }
        };
    }
}

pub struct Kadcast<const N: usize> {
    peer: Peer,
    routes: Arc<RwLock<RoutesList<N>>>,
    filters: Arc<RwLock<FilterList<N>>>,
}

impl<const N: usize> Kadcast<N> {
    pub fn new(conf: Config) -> Self {
        const INIT: Option<AsyncQueue<Message>> = None;
        let routes = Arc::new(RwLock::new([INIT; N]));

        const INIT_FN: Option<BoxedFilter> = None;
        let filters = Arc::new(RwLock::new([INIT_FN; N]));

        Kadcast {
            routes: routes.clone(),
            filters: filters.clone(),
            peer: Peer::new(conf, Listener { routes, filters }).unwrap(),
        }
    }
}

#[async_trait]
impl<const N: usize> crate::Network for Kadcast<N> {
    async fn broadcast(&self, msg: &Message) -> anyhow::Result<()> {
        let height = match msg.metadata {
            Some(Metadata { height: 0, .. }) => return Ok(()),
            Some(Metadata { height, .. }) => Some(height - 1),
            None => None,
        };

        self.peer.broadcast(&frame::PDU::encode(msg)?, height).await;

        Ok(())
    }

    async fn send(
        &self,
        msg: &Message,
        dst: Vec<String>,
    ) -> anyhow::Result<()> {
        self.peer
            .send(
                &[0u8; 8],
                std::net::SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    8080,
                ),
            )
            .await;

        Ok(())
    }

    /// Route any message of the specified type to this queue.
    async fn add_route(
        &mut self,
        msg_type: u8,
        queue: AsyncQueue<Message>,
    ) -> anyhow::Result<()> {
        let mut guard = self.routes.write().await;

        let mut route = guard
            .get_mut(msg_type as usize)
            .expect("should be a valid type");

        assert!(route.is_none(), "msg type already registered");

        *route = Some(queue);

        Ok(())
    }

    async fn add_filter(
        &mut self,
        msg_type: u8,
        filter_fn: BoxedFilter,
    ) -> anyhow::Result<()> {
        let mut guard = self.filters.write().await;

        let mut filter = guard
            .get_mut(msg_type as usize)
            .expect("should be valid type");

        *filter = Some(filter_fn);

        Ok(())
    }
}
