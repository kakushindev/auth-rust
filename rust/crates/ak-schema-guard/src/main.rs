//! `ak-schema-guard`: snapshot the authentik `PostgreSQL` schema and verify a
//! database against the committed baseline. Any difference is a
//! release-blocking failure (exit code 1).
#![expect(clippy::print_stdout, clippy::print_stderr, reason = "CLI output")]

use std::{path::PathBuf, process::ExitCode};

use ak_schema_guard::{Snapshot, snapshot};
use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;

#[derive(Parser)]
#[command(about = "authentik PostgreSQL schema contract guard")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a snapshot of the database schema as JSON.
    Snapshot {
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare the database against a baseline snapshot.
    Verify {
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long)]
        baseline: PathBuf,
    },
    /// Compare two snapshot files.
    Diff {
        baseline: PathBuf,
        candidate: PathBuf,
    },
}

fn load(path: &PathBuf) -> Result<Snapshot, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let snap: Snapshot =
        serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    if !snap.is_consistent() {
        return Err(format!(
            "{}: fingerprints do not match contents",
            path.display()
        ));
    }
    Ok(snap)
}

async fn capture(database_url: &str) -> Result<Snapshot, String> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    // Read-only by construction: the guard must never alter what it checks.
    sqlx::query("set session characteristics as transaction read only")
        .execute(&pool)
        .await
        .map_err(|e| format!("read-only session: {e}"))?;
    snapshot(&pool).await.map_err(|e| format!("snapshot: {e}"))
}

fn report(baseline: &Snapshot, candidate: &Snapshot) -> ExitCode {
    let diff = baseline.diff(candidate);
    if diff.is_empty() {
        println!(
            "schema matches baseline (fingerprint {})",
            baseline.fingerprint
        );
        return ExitCode::SUCCESS;
    }
    println!(
        "SCHEMA DRIFT: baseline {} != candidate {}",
        baseline.fingerprint, candidate.fingerprint
    );
    for (section, d) in diff {
        println!(
            "[{section}] +{} -{} ~{}",
            d.added.len(),
            d.removed.len(),
            d.changed.len()
        );
        for key in d.added {
            println!("  + {key}");
        }
        for key in d.removed {
            println!("  - {key}");
        }
        for (key, before, after) in d.changed {
            println!("  ~ {key}\n      baseline:  {before}\n      candidate: {after}");
        }
    }
    ExitCode::FAILURE
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Snapshot { database_url, out } => capture(&database_url).await.and_then(|s| {
            let json = serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?;
            std::fs::write(&out, json + "\n").map_err(|e| format!("{}: {e}", out.display()))?;
            let objects: usize = s
                .sections
                .values()
                .map(std::collections::BTreeMap::len)
                .sum();
            println!(
                "wrote {} ({objects} objects, fingerprint {})",
                out.display(),
                s.fingerprint
            );
            Ok(ExitCode::SUCCESS)
        }),
        Command::Verify {
            database_url,
            baseline,
        } => match (load(&baseline), capture(&database_url).await) {
            (Ok(b), Ok(c)) => Ok(report(&b, &c)),
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
        Command::Diff {
            baseline,
            candidate,
        } => load(&baseline).and_then(|b| load(&candidate).map(|c| report(&b, &c))),
    };
    result.unwrap_or_else(|e| {
        eprintln!("error: {e}");
        ExitCode::from(2)
    })
}
