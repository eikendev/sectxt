mod network;
mod settings;
mod status;
mod website;

use futures::channel::mpsc::channel;
use futures::{Stream, StreamExt};
use lazy_static::*;
use reqwest::Client;
use sectxtlib::SecurityTxtOptions;
use settings::Settings;
use status::Status;
use std::io::BufRead;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use website::Website;

fn stdin(threads: usize) -> impl Stream<Item = String> {
    let (mut tx, rx) = channel(threads);

    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            loop {
                let status = tx.try_send(line.to_owned());

                match status {
                    Err(e) if e.is_full() => continue,
                    _ => break,
                }
            }
        }
    });

    rx
}

async fn process_line(line: String, client: &Client, options: &SecurityTxtOptions, quiet: bool) -> Status {
    let mut line = line.trim().to_lowercase();
    if !line.starts_with("http") {
        line = format!("https://{line}");
    }
    let website = Website::try_from(&line[..]);

    match website {
        Ok(website) => website.get_status(client, options, quiet).await,
        Err(e) => {
            if !quiet {
                info!(domain = &line, error = e.to_string(), status = "ERR");
            }

            Status {
                domain: line,
                available: false,
            }
        }
    }
}

#[tokio::main]
async fn process_domains(s: &'static Settings) -> (u64, u64) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(s.timeout))
        .build()
        .unwrap();

    let options: SecurityTxtOptions = Default::default();

    let statuses = stdin(s.threads)
        .map(|input| {
            let client = &client;
            let options = &options;
            async move { process_line(input, client, options, s.quiet).await }
        })
        .buffer_unordered(s.threads);

    let count: (u64, u64) = statuses
        .fold((0, 0), |acc, status: Status| async move {
            match s {
                _ if status.available => (acc.0 + 1, acc.1 + 1),
                _ => (acc.0 + 1, acc.1),
            }
        })
        .await;

    count
}

fn setup_logger() {
    let format_layer = fmt::layer()
        .with_level(true)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .without_time()
        .json();

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(format_layer)
        .init();
}

fn main() {
    human_panic::setup_panic!();

    lazy_static! {
        static ref SETTINGS: Settings = argh::from_env();
    }

    setup_logger();

    let count = process_domains(&SETTINGS);

    if SETTINGS.print_stats {
        println!("{}/{}", count.0, count.1);
    }
}
