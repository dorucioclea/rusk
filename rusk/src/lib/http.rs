// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(unused)]

#[cfg(feature = "node")]
mod chain;
mod event;
#[cfg(feature = "prover")]
mod prover;
#[cfg(feature = "node")]
mod rusk;
mod stream;

pub(crate) use event::{
    BinaryWrapper, DataType, ExecutionError, MessageResponse as EventResponse,
    RequestData, Target,
};
use hyper::http::{HeaderName, HeaderValue};
use rusk_abi::Event;
use tracing::info;

use std::borrow::Cow;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::ToSocketAddrs;
use tokio::sync::{broadcast, mpsc};
use tokio::{io, task};

use hyper::server::conn::Http;
use hyper::service::Service;
use hyper::{body, Body, Request, Response, StatusCode};
use hyper_tungstenite::{tungstenite, HyperWebsocket};

use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, Message};

use futures_util::stream::iter as stream_iter;
use futures_util::{SinkExt, StreamExt};

#[cfg(feature = "node")]
use crate::chain::{Rusk, RuskNode};
use crate::VERSION;

use self::event::{MessageRequest, ResponseData};
use self::stream::{Listener, Stream};

const RUSK_VERSION_HEADER: &str = "Rusk-Version";

pub struct HttpServer {
    pub handle: task::JoinHandle<()>,
    local_addr: SocketAddr,
    pub _shutdown: broadcast::Sender<Infallible>,
}

impl HttpServer {
    pub async fn bind<A, H, P1, P2>(
        handler: H,
        addr: A,
        cert_and_key: Option<(P1, P2)>,
    ) -> io::Result<Self>
    where
        A: ToSocketAddrs,
        H: HandleRequest,
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        let listener = match cert_and_key {
            Some(cert_and_key) => Listener::bind_tls(addr, cert_and_key).await,
            None => Listener::bind(addr).await,
        }?;

        let (shutdown_sender, shutdown_receiver) = broadcast::channel(1);

        let local_addr = listener.local_addr()?;

        info!("Starting HTTP Listener to {local_addr}");

        let handle =
            task::spawn(listening_loop(handler, listener, shutdown_receiver));

        Ok(Self {
            handle,
            local_addr,
            _shutdown: shutdown_sender,
        })
    }
}

pub struct DataSources {
    #[cfg(feature = "node")]
    pub rusk: Rusk,
    #[cfg(feature = "node")]
    pub node: RuskNode,
    #[cfg(feature = "prover")]
    pub prover: rusk_prover::LocalProver,
}

#[async_trait]
impl HandleRequest for DataSources {
    async fn handle(
        &self,
        request: &MessageRequest,
    ) -> anyhow::Result<ResponseData> {
        info!(
            "Received {:?}:{} request",
            request.event.target, request.event.topic
        );
        request.check_rusk_version()?;
        match request.event.to_route() {
            #[cfg(feature = "prover")]
            // target `rusk` shall be removed in future versions
            (_, "rusk", topic) | (_, "prover", topic)
                if topic.starts_with("prove_") =>
            {
                self.prover.handle(request).await
            }
            #[cfg(feature = "node")]
            (Target::Contract(_), ..) | (_, "rusk", _) => {
                self.rusk.handle(request).await
            }
            #[cfg(feature = "node")]
            (_, "Chain", _) => self.node.handle(request).await,
            _ => Err(anyhow::anyhow!("unsupported target type")),
        }
    }
}

async fn listening_loop<H>(
    handler: H,
    listener: Listener,
    mut shutdown: broadcast::Receiver<Infallible>,
) where
    H: HandleRequest,
{
    let handler = Arc::new(handler);
    let http = Http::new();

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                break;
            }
            r = listener.accept() => {
                let stream = match r {
                    Ok(stream) => stream,
                    Err(_) => break,
                };

                let service = ExecutionService {
                    sources: handler.clone(),
                    shutdown: shutdown.resubscribe()
                };
                let conn = http.serve_connection(stream, service).with_upgrades();

                task::spawn(conn);
            }
        }
    }
}

async fn handle_stream<H: HandleRequest>(
    sources: Arc<H>,
    websocket: HyperWebsocket,
    target: Target,
    mut shutdown: broadcast::Receiver<Infallible>,
) {
    let mut stream = match websocket.await {
        Ok(stream) => stream,
        Err(_) => return,
    };

    // Add this block to disable requests through websockets
    // {
    //     let _ = stream
    //         .close(Some(CloseFrame {
    //             code: CloseCode::Unsupported,
    //             reason: Cow::from("Websocket is currently unsupported"),
    //         }))
    //         .await;
    //     #[allow(clippy::needless_return)]
    //     return;
    // }

    let (responder, mut responses) = mpsc::unbounded_channel::<EventResponse>();

    'outer: loop {
        tokio::select! {
            // If the server shuts down we send a close frame to the client
            // and stop.
            _ = shutdown.recv() => {
                let _ = stream.close(Some(CloseFrame {
                    code: CloseCode::Away,
                    reason: Cow::from("Shutting down"),
                })).await;
                break;
            }

            rsp = responses.recv() => {
                // `responder` is never dropped so this can never be `None`
                let rsp = rsp.unwrap();

                if let DataType::Channel(c) = rsp.data {
                    let mut datas = stream_iter(c).map(|e| {
                        EventResponse {
                            data: e.into(),
                            headers: rsp.headers.clone(),
                            error: None
                        }
                    });//.await;
                    while let Some(c) = datas.next().await {
                        let rsp = serde_json::to_string(&c).unwrap_or_else(|err| {
                            serde_json::to_string(
                                &EventResponse::from_error(
                                    format!("Failed serializing response: {err}")
                                )).expect("serializing error response should succeed")
                            });

                        // If we error in sending the message we send a close frame
                        // to the client and stop.
                        if stream.send(Message::Text(rsp)).await.is_err() {
                            let _ = stream.close(Some(CloseFrame {
                            code: CloseCode::Error,
                            reason: Cow::from("Failed sending response"),
                            })).await;
                            // break;
                        }
                    }


                } else {
                    // Serialize the response to text. If this does not succeed,
                    // we simply serialize an error response.
                    let rsp = serde_json::to_string(&rsp).unwrap_or_else(|err| {
                        serde_json::to_string(
                            &EventResponse::from_error(
                                format!("Failed serializing response: {err}")
                            )).expect("serializing error response should succeed")
                        });

                    // If we error in sending the message we send a close frame
                    // to the client and stop.
                    if stream.send(Message::Text(rsp)).await.is_err() {
                        let _ = stream.close(Some(CloseFrame {
                        code: CloseCode::Error,
                        reason: Cow::from("Failed sending response"),
                        })).await;
                        break;
                    }
                }
            }

            msg = stream.next() => {

                let mut req = match msg {
                    Some(Ok(msg)) => match msg {
                        // We received a text request.
                        Message::Text(msg) => {
                            serde_json::from_str(&msg)
                                .map_err(|err| anyhow::anyhow!("Failed deserializing request: {err}"))
                        },
                        // We received a binary request.
                        Message::Binary(msg) => {
                            MessageRequest::parse(&msg)
                                .map_err(|err| anyhow::anyhow!("Failed deserializing request: {err}"))
                        }
                        // Any other type of message is unsupported.
                        _ => Err(anyhow::anyhow!("Only text and binary messages are supported"))
                    }
                    // Errored while receiving the message, we will
                    // close the stream and return a close frame.
                    Some(Err(err)) => {
                        Err(anyhow::anyhow!("Failed receiving message: {err}"))
                    }
                    // The stream has stopped producing messages, and we
                    // should close it and stop. The client likely has done
                    // this on purpose, and it's a part of the normal
                    // operation of the server.
                    None => {
                        let _ = stream.close(Some(CloseFrame {
                            code: CloseCode::Normal,
                            reason: Cow::from("Stream stopped"),
                        })).await;
                        break;
                    }
                };
                match req {
                    // We received a valid request and should spawn a new task to handle it
                    Ok(mut req) => {
                        req.event.target=target.clone();
                        task::spawn(handle_execution(
                            sources.clone(),
                            req,
                            responder.clone(),
                        ));
                    },
                    Err(e) => {
                        let _ = stream.close(Some(CloseFrame {
                            code: CloseCode::Error,
                            reason: Cow::from(e.to_string()),
                        })).await;
                        break;
                    }
                }

            }
        }
    }
}

struct ExecutionService<H> {
    sources: Arc<H>,
    shutdown: broadcast::Receiver<Infallible>,
}

impl<H> Service<Request<Body>> for ExecutionService<H>
where
    H: HandleRequest,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<
        Box<
            dyn Future<Output = Result<Self::Response, Self::Error>>
                + Send
                + 'static,
        >,
    >;

    fn poll_ready(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Handle the HTTP request.
    ///
    /// A request may be a "normal" request, or a WebSocket upgrade request. In
    /// the former case, the request is handled on the spot, while in the
    /// latter task running the stream handler loop is spawned.
    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let sources = self.sources.clone();
        let shutdown = self.shutdown.resubscribe();

        Box::pin(async move {
            let response = handle_request(req, shutdown, sources).await;
            response.or_else(|error| {
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(error.to_string()))
                    .expect("Failed to build response"))
            })
        })
    }
}

// If the request is a WebSocket upgrade request, we upgrade the connection
// and spawn a task to handle it. Each WebSocket connection has its own
// associated UUID, which is used to identify the connection.
//
// If the request is not a WebSocket upgrade request, there are two
// possibilities:
//
// 1. The request is a normal request (POST)
// 2. The request is a (un)subscribe request to some WebSocket topic
async fn handle_request_v2<H>(
    mut req: Request<Body>,
    mut shutdown: broadcast::Receiver<Infallible>,
    sources: Arc<H>,
) -> Result<Response<Body>, ExecutionError>
where
    H: HandleRequest,
{
    if hyper_tungstenite::is_upgrade_request(&req) {
        let target = req.uri().path().try_into()?;

        let (response, websocket) = hyper_tungstenite::upgrade(&mut req, None)?;
        task::spawn(handle_stream_v2(sources, websocket, target, shutdown));

        Ok(response)
    } else {
    }
}

async fn handle_request<H>(
    mut req: Request<Body>,
    mut shutdown: broadcast::Receiver<Infallible>,
    sources: Arc<H>,
) -> Result<Response<Body>, ExecutionError>
where
    H: HandleRequest,
{
    let path = req.uri().path();

    if path.starts_with("/v2") {
        return handle_request_v2(req, shutdown, sources).await;
    }

    if hyper_tungstenite::is_upgrade_request(&req) {
        let target = req.uri().path().try_into()?;

        let (response, websocket) = hyper_tungstenite::upgrade(&mut req, None)?;
        task::spawn(handle_stream(sources, websocket, target, shutdown));

        Ok(response)
    } else {
        let (execution_request, binary_resp) =
            MessageRequest::from_request(req).await?;

        let mut resp_headers = execution_request.x_headers();

        let (responder, mut receiver) = mpsc::unbounded_channel();
        handle_execution(sources, execution_request, responder).await;

        let execution_response = receiver
            .recv()
            .await
            .expect("An execution should always return a response");
        resp_headers.extend(execution_response.headers.clone());
        let mut resp = execution_response.into_http(binary_resp)?;

        for (k, v) in resp_headers {
            let k = HeaderName::from_str(&k)?;
            let v = match v {
                serde_json::Value::String(s) => HeaderValue::from_str(&s),
                serde_json::Value::Null => HeaderValue::from_str(""),
                _ => HeaderValue::from_str(&v.to_string()),
            }?;
            resp.headers_mut().append(k, v);
        }

        Ok(resp)
    }
}

async fn handle_execution<H>(
    sources: Arc<H>,
    request: MessageRequest,
    responder: mpsc::UnboundedSender<EventResponse>,
) where
    H: HandleRequest,
{
    let mut rsp = sources
        .handle(&request)
        .await
        .map(|data| {
            let (data, mut headers) = data.into_inner();
            headers.append(&mut request.x_headers());
            EventResponse {
                data,
                error: None,
                headers,
            }
        })
        .unwrap_or_else(|e| request.to_error(e.to_string()));

    rsp.set_header(RUSK_VERSION_HEADER, serde_json::json!(*VERSION));
    let _ = responder.send(rsp);
}

#[async_trait]
pub trait HandleRequest: Send + Sync + 'static {
    async fn handle(
        &self,
        request: &MessageRequest,
    ) -> anyhow::Result<ResponseData>;
}

#[cfg(test)]
mod tests {
    use std::{fs, thread};

    use super::*;
    use event::Event as EventRequest;

    use std::net::TcpStream;
    use tungstenite::client;

    /// A [`HandleRequest`] implementation that returns the same data
    struct TestHandle;

    const STREAMED_DATA: &[&[u8; 16]] = &[
        b"I am call data 0",
        b"I am call data 1",
        b"I am call data 2",
        b"I am call data 3",
    ];

    #[async_trait]
    impl HandleRequest for TestHandle {
        async fn handle(
            &self,
            request: &MessageRequest,
        ) -> anyhow::Result<ResponseData> {
            let response = match request.event.to_route() {
                (_, _, "stream") => {
                    let (sender, rec) = std::sync::mpsc::channel();
                    thread::spawn(move || {
                        for f in STREAMED_DATA.iter() {
                            sender.send(f.to_vec()).unwrap()
                        }
                    });
                    ResponseData::new(rec)
                }
                _ => ResponseData::new(request.event_data().to_vec()),
            };
            Ok(response)
        }
    }

    #[tokio::test]
    async fn http_query() {
        let cert_and_key: Option<(String, String)> = None;

        let server = HttpServer::bind(TestHandle, "localhost:0", cert_and_key)
            .await
            .expect("Binding the server to the address should succeed");

        let data = Vec::from(&b"I am call data 0"[..]);
        let data = RequestData::Binary(BinaryWrapper { inner: data });

        let event = EventRequest {
            target: Target::None,
            data,
            topic: "topic".into(),
        };

        let request = serde_json::to_vec(&event)
            .expect("Serializing request should succeed");

        let client = reqwest::Client::new();
        let response = client
            .post(format!("http://{}/01/target", server.local_addr))
            .body(Body::from(request))
            .send()
            .await
            .expect("Requesting should succeed");

        let response_bytes =
            response.bytes().await.expect("There should be a response");
        let response_bytes =
            hex::decode(response_bytes).expect("data to be hex encoded");
        let request_bytes = event.data.as_bytes();

        assert_eq!(
            request_bytes, response_bytes,
            "Data received the same as sent"
        );
    }

    #[tokio::test]
    async fn https_query() {
        let cert_path = "tests/assets/cert.pem";
        let key_path = "tests/assets/key.pem";

        let cert_bytes = fs::read(cert_path).expect("cert file should exist");
        let certificate = reqwest::tls::Certificate::from_pem(&cert_bytes)
            .expect("cert should be valid");

        let server = HttpServer::bind(
            TestHandle,
            "localhost:0",
            Some((cert_path, key_path)),
        )
        .await
        .expect("Binding the server to the address should succeed");

        let data = Vec::from(&b"I am call data 0"[..]);
        let data = RequestData::Binary(BinaryWrapper { inner: data });

        let event = EventRequest {
            target: Target::None,
            data,
            topic: "topic".into(),
        };

        let request = serde_json::to_vec(&event)
            .expect("Serializing request should succeed");

        let client = reqwest::ClientBuilder::new()
            .add_root_certificate(certificate)
            .danger_accept_invalid_certs(true)
            .build()
            .expect("creating client should succeed");

        let response = client
            .post(format!(
                "https://localhost:{}/01/target",
                server.local_addr.port()
            ))
            .body(Body::from(request))
            .send()
            .await
            .expect("Requesting should succeed");

        let response_bytes =
            response.bytes().await.expect("There should be a response");
        let response_bytes =
            hex::decode(response_bytes).expect("data to be hex encoded");
        let request_bytes = event.data.as_bytes();

        assert_eq!(
            request_bytes, response_bytes,
            "Data received the same as sent"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn websocket_queries() {
        let cert_and_key: Option<(String, String)> = None;

        let server = HttpServer::bind(TestHandle, "localhost:0", cert_and_key)
            .await
            .expect("Binding the server to the address should succeed");

        let stream = TcpStream::connect(server.local_addr)
            .expect("Connecting to the server should succeed");

        let ws_uri = format!("ws://{}/01/stream", server.local_addr);
        let (mut stream, _) = client(ws_uri, stream)
            .expect("Handshake with the server should succeed");

        let event = EventRequest {
            target: Target::None,
            data: RequestData::Text("Not used".into()),
            topic: "stream".into(),
        };
        let request_x_header: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"X-requestid": "100"}"#)
                .expect("headers to be serialized");

        let request = MessageRequest {
            event,
            headers: request_x_header.clone(),
        };

        let request = serde_json::to_string(&request).unwrap();

        stream
            .send(Message::Text(request))
            .expect("Sending request to the server should succeed");

        let mut responses = vec![];

        while responses.len() < STREAMED_DATA.len() {
            let msg = stream
                .read()
                .expect("Response should be received without error");

            let msg = match msg {
                Message::Text(msg) => msg,
                _ => panic!("Shouldn't receive anything but text"),
            };
            let response: EventResponse = serde_json::from_str(&msg)
                .expect("Response should deserialize successfully");

            let mut response_x_header = response.headers.clone();
            response_x_header.retain(|k, _| k.to_lowercase().starts_with("x-"));
            assert_eq!(
                response_x_header, request_x_header,
                "x-headers to be propagated back"
            );
            assert!(matches!(response.error, None), "There should be noerror");
            match response.data {
                DataType::Binary(BinaryWrapper { inner }) => {
                    responses.push(inner);
                }
                _ => panic!("WS stream is supposed to return binary data"),
            }
        }

        for (idx, response) in responses.iter().enumerate() {
            let expected_data = STREAMED_DATA[idx];
            assert_eq!(
                &response[..],
                expected_data,
                "Response data should be the same as the request `fn_args`"
            );
        }
    }
}
