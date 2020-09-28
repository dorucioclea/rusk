// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.
#[cfg(not(target_os = "windows"))]
mod unix;
mod version;

use clap::{App, Arg};
use futures::stream::TryStreamExt;
use rusk::services::echoer::EchoerServer;
use rusk::Rusk;
use rustc_tools_util::{get_version_info, VersionInfo};
use std::path::Path;
use tokio::net::UnixListener;
use tonic::transport::Server;
use version::show_version;

/// Default UDS path that Rusk GRPC-server will connect to.
pub const SOCKET_PATH: &'static str = "/tmp/rusk_listener";

/// Default port that Rusk GRPC-server will listen to.
pub(crate) const PORT: &'static str = "8585";
/// Default host_address that Rusk GRPC-server will listen to.
pub(crate) const HOST_ADDRESS: &'static str = "127.0.0.1";

#[tokio::main]
async fn main() {
    let crate_info = get_version_info!();
    let matches = App::new(&crate_info.crate_name)
        .version(show_version(crate_info).as_str())
        .author("Dusk Network B.V. All Rights Reserved.")
        .about("Rusk Server node.")
        .arg(
            Arg::with_name("socket")
                .short("s")
                .long("socket")
                .value_name("socket")
                .help("Path for setting up the UDS ")
                .default_value(SOCKET_PATH)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ipc_method")
                .long("ipc_method")
                .value_name("ipc_method")
                .possible_values(&["uds", "tcp_ip"])
                .help("Inter-Process communication protocol you want to use ")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("port")
                .help("Port you want to use ")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("host")
                .short("h")
                .long("host")
                .value_name("host")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .value_name("LOG")
                .possible_values(&["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Output log level")
                .takes_value(true),
        )
        .get_matches();

    // Match tracing desired level.
    let log = match matches
        .value_of("log-level")
        .expect("Failed parsing log-level arg")
    {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => unreachable!(),
    };

    // Generate a subscriber with the desired log level.
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(log)
        .finish();
    // Set the subscriber as global.
    // so this subscriber will be used as the default in all threads for the remainder
    // of the duration of the program, similar to how `loggers` work in the `log` crate.
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed on subscribe tracing");

    // Match the desired IPC method. Or set the default one depending on the OS used.
    // Then startup rusk with the final values.
    let res = match matches.value_of("ipc_method") {
        Some(method) => match (cfg!(windows), method) {
            (_, "tcp_ip") => {
                startup_with_tcp_ip(
                    matches.value_of("host").unwrap_or_else(|| HOST_ADDRESS),
                    matches.value_of("port").unwrap_or_else(|| PORT),
                )
                .await
            }
            (true, "uds") => {
                panic!("Windows does not support Unix Domain Sockets");
            }
            (false, "uds") => {
                startup_with_uds(
                    matches.value_of("socket").unwrap_or_else(|| SOCKET_PATH),
                )
                .await
            }
            (_, _) => unreachable!(),
        },
        None => {
            if cfg!(windows) {
                startup_with_tcp_ip(
                    matches.value_of("host").unwrap_or_else(|| HOST_ADDRESS),
                    matches.value_of("port").unwrap_or_else(|| PORT),
                )
                .await
            } else {
                startup_with_uds(
                    matches.value_of("socket").unwrap_or_else(|| SOCKET_PATH),
                )
                .await
            }
        }
    };
    match res {
        Ok(()) => (),
        Err(e) => eprintln!("{}", e),
    };
}

#[cfg(not(target_os = "windows"))]
async fn startup_with_uds(
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::fs::create_dir_all(Path::new(path).parent().unwrap()).await?;

    let mut uds = UnixListener::bind(path)?;

    let rusk = Rusk::default();

    Server::builder()
        .add_service(EchoerServer::new(rusk))
        .serve_with_incoming(uds.incoming().map_ok(unix::UnixStream))
        .await?;

    Ok(())
}

async fn startup_with_tcp_ip(
    host: &str,
    port: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut full_address = host.to_string();
    full_address.extend(":".chars());
    full_address.extend(port.to_string().chars());
    let addr: std::net::SocketAddr = full_address.parse()?;
    let rusk = Rusk::default();

    // Build the Server with the `Echo` service attached to it.
    Ok(Server::builder()
        .add_service(EchoerServer::new(rusk))
        .serve(addr)
        .await?)
}