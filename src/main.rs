mod parse;
mod settings;
mod types;

use futures::channel::mpsc::channel;
use futures::{Stream, StreamExt};
use lazy_static::*;
use settings::Settings;
use std::io::BufRead;
use std::time::Duration;
use types::Website;

fn stdin(threads: usize) -> impl Stream<Item = String> {
    let (mut tx, rx) = channel(threads);

    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().flatten() {
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

#[tokio::main]
async fn process_domains(s: &'static Settings) -> (u64, u64) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(s.timeout))
        .build()
        .unwrap();

    let statuses = stdin(s.threads)
        .map(|x| {
            let client = &client;

            async move {
                let website = Website::from(&x[..]);
                return website.get_status(client, s.quiet).await;
            }
        })
        .buffer_unordered(s.threads);

    let count: (u64, u64) = statuses
        .fold((0, 0), |acc, s| async move {
            match s {
                _ if s.available => (acc.0 + 1, acc.1 + 1),
                _ => (acc.0 + 1, acc.1),
            }
        })
        .await;

    count
}

fn process_result(total: u64, available: u64) {
    println!("{}/{}", available, total);
}

fn main() {
    human_panic::setup_panic!();

    lazy_static! {
        static ref SETTINGS: Settings = argh::from_env();
    }

    let count = process_domains(&SETTINGS);

    if !SETTINGS.quiet {
        process_result(count.0, count.1);
    }
}
