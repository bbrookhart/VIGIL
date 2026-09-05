#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vigil_daemon::{Authority, Config, Request, Result};
use vigil_local::LocalProfile;

#[derive(Parser)]
#[command(about = "Experimental VIGIL authority service; does not execute tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        agent_uid: u32,
        #[arg(long)]
        operator_uid: u32,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long, default_value = "developer-restricted")]
        profile: LocalProfile,
    },
    Call {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        server_uid: u32,
        /// A single protocol request as JSON.
        #[arg(long)]
        request: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve {
            state_dir,
            socket,
            agent_uid,
            operator_uid,
            workspace,
            profile,
        } => {
            let authority = Authority::open(
                &state_dir,
                Config {
                    agent_uid,
                    operator_uid,
                    workspace,
                    profile,
                },
            )?;
            vigil_daemon::serve(&socket, authority).await
        }
        Command::Call {
            socket,
            server_uid,
            request,
        } => {
            let request: Request = serde_json::from_str(&request)?;
            let response = vigil_daemon::call(&socket, server_uid, &request).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                return Err("authority denied request".into());
            }
            Ok(())
        }
    }
}
