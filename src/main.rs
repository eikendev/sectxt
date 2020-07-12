mod parse;
mod types;

use clap::{crate_authors, crate_description, crate_name, crate_version, load_yaml, value_t_or_exit};
use futures::channel::mpsc::channel;
use futures::{Stream, StreamExt};
use std::io::BufRead;
use std::time::Duration;
use types::Website;

fn stdin(threads: usize) -> impl Stream<Item = String> {
    let (mut tx, rx) = channel(threads);

    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if let Ok(line) = line {
                loop {
                    let status = tx.try_send(line.to_owned());

                    match status {
                        Err(e) if e.is_full() => continue,
                        _ => break,
                    }
                }
            }
        }
    });

    rx
}

#[tokio::main]
async fn process_domains(threads: usize, timeout: u64, quiet: bool) -> (u64, u64) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .unwrap();

    let statuses = stdin(threads)
        .map(|x| {
            let client = &client;

            async move {
                let website = Website::from(&x[..]);
                return website.get_status(client, quiet).await;
            }
        })
        .buffer_unordered(threads);

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
    let args_yaml = load_yaml!("args.yml");

    let matches = clap::App::from_yaml(args_yaml)
        .name(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .get_matches();

    let threads = value_t_or_exit!(matches.value_of("threads"), usize);
    let timeout = value_t_or_exit!(matches.value_of("timeout"), u64);
    let quiet = matches.is_present("quiet");

    let count = process_domains(threads, timeout, quiet);

    if !quiet {
        process_result(count.0, count.1);
    }
}
