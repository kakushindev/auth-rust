//! authentik-rs: `healthcheck` as 2026.2.7's Go `cmd/server/healthcheck.go`
//! runs it. `lifecycle/ak healthcheck` passes the mode from the mode file;
//! the worker is the Python process from `python -m manage worker`, which
//! the Helm chart's worker liveness probe checks through its PID file.

use std::{env, fs, path::PathBuf};

use ak_common::config;
use argh::FromArgs;
use eyre::{Result, eyre};
use nix::{sys::signal::kill, unistd::Pid};
use reqwest::blocking::Client;
use tracing::{debug, info, warn};

#[derive(Debug, FromArgs, PartialEq)]
/// Run healthcheck
#[argh(subcommand, name = "healthcheck")]
pub(super) struct Cli {
    #[argh(positional)]
    mode: String,
}

pub(super) fn run(args: &Cli) -> Result<()> {
    debug!(mode = args.mode, "checking health");
    match args.mode.to_lowercase().as_str() {
        "server" => check_server(),
        "worker" => check_worker(),
        // Not a 2026.2.7 server mode: upstream Rust's standalone proxy
        // outpost, which 2026.2.7 ships as a separate Go image.
        #[cfg(feature = "proxy")]
        "proxy" => check_proxy(),
        _ => {
            warn!("Invalid mode");
            Err(eyre!("invalid mode {}", args.mode))
        }
    }
}

/// `checkServer`: `HEAD http://<listen.http><web.path>-/health/live/` over
/// TCP, following redirects and without a timeout like Go's `http.Client`;
/// any status below 400 is healthy.
fn check_server() -> Result<()> {
    config::init()?;
    let config = config::get();
    let addr = config
        .listen
        .http
        .first()
        .ok_or_else(|| eyre!("no listen.http address"))?;
    let url = format!("http://{addr}{}-/health/live/", config.web.path);
    let response = Client::builder()
        .user_agent("goauthentik.io/healthcheck")
        .timeout(None)
        .build()?
        .head(url)
        .send()
        .inspect_err(|err| warn!(?err, "failed to send healthcheck request"))?;
    if response.status().as_u16() >= 400 {
        warn!(status = response.status().as_u16(), "unhealthy status code");
        return Err(eyre!("unhealthy status code {}", response.status()));
    }
    debug!("successfully checked health");
    Ok(())
}

/// Upstream Rust's proxy outpost healthcheck, unchanged.
#[cfg(feature = "proxy")]
fn check_proxy() -> Result<()> {
    let response = Client::builder()
        .user_agent("goauthentik.io/healthcheck")
        .unix_socket(crate::metrics::socket_path())
        .build()?
        .get("http://localhost/outpost.goauthentik.io/ping")
        .send()?;
    if !response.status().is_success() {
        return Err(eyre!("unhealthy status code {}", response.status()));
    }
    info!("successfully checked health");
    Ok(())
}

/// Go's `os.TempDir()/authentik-worker.pid`, written by
/// `python -m manage worker --pid-file`.
fn worker_pid_file() -> PathBuf {
    env::temp_dir().join("authentik-worker.pid")
}

/// `checkWorker`: the PID in the worker's PID file must accept signal 0.
fn check_worker() -> Result<()> {
    let pid = fs::read_to_string(worker_pid_file())
        .inspect_err(|err| warn!(?err, "failed to check worker PID file"))?;
    // strconv.Atoi: optional sign, decimal digits.
    let pid: i32 = pid
        .trim()
        .parse()
        .inspect_err(|err| warn!(?err, "failed to find worker process PID"))?;
    // os.Process.Signal refuses these before signalling.
    if pid == 0_i32 || pid == -1_i32 {
        warn!("failed to signal worker process");
        return Err(eyre!("invalid worker PID {pid}"));
    }
    kill(Pid::from_raw(pid), None)
        .inspect_err(|err| warn!(?err, "failed to signal worker process"))?;
    info!("successfully checked health");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process;

    use super::*;

    /// One test, since `TMPDIR` is process-wide.
    #[test]
    fn worker_pid_check() {
        let dir = tempfile::tempdir().expect("temp dir");
        #[expect(unsafe_code, reason = "testing")]
        // SAFETY: testing
        unsafe {
            env::set_var("TMPDIR", dir.path());
        }
        let check = |contents: &str| {
            fs::write(dir.path().join("authentik-worker.pid"), contents).expect("write");
            check_worker()
        };
        check(&format!(" {}\n", process::id())).expect("own PID is alive");
        check(&format!("+{}", process::id())).expect("Atoi accepts a sign");
        // PID_MAX_LIMIT is 2^22, so this PID cannot exist.
        for contents in ["2147483647", "0", "-1", "abc", ""] {
            assert!(check(contents).is_err(), "{contents:?}");
        }
    }

    #[test]
    fn invalid_mode() {
        for mode in ["allinone", "nope", ""] {
            let cli = Cli {
                mode: mode.to_owned(),
            };
            assert!(run(&cli).is_err(), "{mode}");
        }
    }
}
