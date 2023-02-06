// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod task;
mod version;

use clap::Parser;
use microkelvin::{BackendCtor, DiskBackend, Persistence};
use rusk_recovery_tools::theme::Theme;
use std::error::Error;
use std::{env, io};
use std::{fs, path::PathBuf};
use tracing::info;
use version::VERSION_BUILD;

use rusk_recovery_tools::state::{deploy, restore_state, tar, Snapshot};

#[derive(Parser, Debug)]
#[clap(name = "rusk-recovery-state")]
#[clap(author, version = &VERSION_BUILD[..], about, long_about = None)]
struct Cli {
    /// Sets the profile path
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "PATH",
        env = "RUSK_PROFILE_PATH"
    )]
    profile: PathBuf,

    /// Forces a build/download even if the state is in the profile path.
    #[clap(short = 'f', long, env = "RUSK_FORCE_STATE")]
    force: bool,

    /// Create a state applying the init config specified in this file.
    #[clap(short, long, parse(from_os_str), value_name = "CONFIG")]
    init: Option<PathBuf>,

    /// Sets different levels of verbosity
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,

    /// If specified, the generated state is written on this file instead of
    /// save the state in the profile path.
    #[clap(short, long, parse(from_os_str), takes_value(true))]
    output: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    let config = match args.init {
        Some(path) => fs::read_to_string(path)?,
        None => include_str!("../../config/testnet_remote.toml").into(),
    };
    let snapshot = toml::from_str(&config)?;

    task::run(
        || {
            exec(ExecConfig {
                init: &snapshot,
                force: args.force,
                output_file: args.output.clone(),
            })
        },
        args.profile,
        args.verbose,
    )
}

pub struct ExecConfig<'a> {
    pub init: &'a Snapshot,
    pub force: bool,
    pub output_file: Option<PathBuf>,
}

pub fn exec(config: ExecConfig) -> Result<(), Box<dyn Error>> {
    let theme = Theme::default();
    info!("{} Network state", theme.action("Checking"));

    let _tmpdir = match config.output_file.clone() {
        Some(output) if output.exists() => Err("Output already exists")?,
        Some(_) => {
            let tmp_dir = tempfile::tempdir()?;
            env::set_var("RUSK_STATE_PATH", tmp_dir.path());
            Some(tmp_dir)
        }
        None => None,
    };

    if config.force {
        clean_state()?;
    }

    let state_path = rusk_profile::get_rusk_state_dir()?;
    let id_path = rusk_profile::get_rusk_state_id_path()?;

    let ctor = &BackendCtor::new(|| {
        DiskBackend::new(rusk_profile::get_rusk_state_dir()?)
    });

    // if the state already exists in the expected path, stop early.
    if state_path.exists() && id_path.exists() {
        info!("{} existing state", theme.info("Found"));

        // `restore_state` function requires a backend set to the Persistence.
        //
        // Usually it's instantiated inside the `deploy` function, but in this
        // case that function it's not called at all, so there is the need to
        // explicitly instantiate it.
        Persistence::with_backend(ctor, |_| Ok(()))?;

        let network = restore_state(&id_path)?;
        info!(
            "{} state id at {}",
            theme.success("Checked"),
            id_path.display()
        );
        info!("{} {}", theme.action("Root"), hex::encode(network.root()));

        return Ok(());
    }

    info!("{} new state", theme.info("Building"));

    let state_id = deploy(config.init, ctor)?;

    info!("{} persisted id", theme.success("Storing"));
    state_id.write(&id_path)?;

    let network = restore_state(&id_path)?;
    info!(
        "{} {}",
        theme.action("Final Root"),
        hex::encode(network.root())
    );

    info!(
        "{} network state at {}",
        theme.success("Stored"),
        state_path.display()
    );
    info!(
        "{} persisted id at {}",
        theme.success("Stored"),
        id_path.display()
    );

    if let Some(output) = config.output_file {
        let state_folder = rusk_profile::get_rusk_state_dir()?;
        let input = state_folder.parent().expect("state dir not equal to root");
        info!("{} state into the output file", theme.info("Zipping"),);
        tar::archive(input, &output)?;
    }

    Ok(())
}

fn clean_state() -> Result<(), io::Error> {
    let state_path = rusk_profile::get_rusk_state_dir()?;
    let id_path = rusk_profile::get_rusk_state_id_path()?;

    fs::remove_dir_all(state_path).or_else(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    fs::remove_file(id_path).or_else(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(e)
        }
    })
}