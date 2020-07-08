mod parse;
mod types;

use clap::{crate_authors, crate_description, crate_name, crate_version, load_yaml, value_t_or_exit};
use futures::StreamExt;
use std::io::prelude::*;
use std::time::Duration;
use types::Website;

async fn process_domains(domains: &Vec<String>, threads: usize, timeout: u64, quiet: bool) -> u64 {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .unwrap();

    let responses = futures::stream::iter(domains)
        .map(|x| {
            let client = &client;

            async move {
                let website = Website::from(&x[..]);
                return website.get_status(client, quiet).await;
            }
        })
        .buffer_unordered(threads);

    let count: u64 = responses
        .fold(0, |acc, s| async move {
            match s {
                _ if s.available => acc + 1,
                _ => acc,
            }
        })
        .await;

    count
}

fn process_result(count: u64, total: usize) {
    println!("{}/{}", count, total);
}

// https://stackoverflow.com/a/36374135
fn readlines() -> Vec<String> {
    let v = std::io::stdin().lock().lines().filter_map(|x| x.ok()).collect();
    v
}

#[tokio::main]
async fn main() {
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

    let domains = readlines();

    let count = process_domains(&domains, threads, timeout, quiet).await;

    if !quiet {
        process_result(count, domains.len());
    }
}
