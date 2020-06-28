#[macro_use]
extern crate clap;
extern crate futures;
extern crate reqwest;

use futures::StreamExt;
use std::io::prelude::*;
use std::time::Duration;

fn is_securitytxt(r: reqwest::Response) -> bool {
    match r.status() {
        reqwest::StatusCode::OK => {
            let content_type = r.headers().get("Content-Type").unwrap();
            content_type.to_str().unwrap().starts_with("text/plain")
        }
        _ => false,
    }
}

fn build_urls<'a>(domains: &'a Vec<String>) -> Vec<(&'a str, [String; 2])> {
    let urls: Vec<(&str, [String; 2])> = domains
        .into_iter()
        .map(|x| {
            (
                &x[..],
                [
                    format!("https://{}/.well-known/security.txt", x),
                    format!("https://{}/security.txt", x),
                ],
            )
        })
        .collect();

    urls
}

async fn process_domains(domains: &Vec<String>, threads: usize, timeout: u64) -> u64 {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .unwrap();

    let urls = build_urls(domains);

    let responses = futures::stream::iter(urls)
        .map(|x| {
            let client = &client;
            async move {
                for url in &x.1 {
                    let response = client.get(url).send().await;

                    match response {
                        Ok(r) => {
                            if is_securitytxt(r) {
                                return (x.0, true);
                            }
                        }
                        Err(e) => eprintln!("HTTP request failed: {}", e),
                    }
                }

                (x.0, false)
            }
        })
        .buffer_unordered(threads);

    let count: u64 = responses
        .fold(0, |acc, r| async move {
            match r {
                (domain, true) => {
                    println!("{} ... success", domain);
                    acc + 1
                }
                (domain, false) => {
                    println!("{} ... failure", domain);
                    acc
                }
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
    let v = std::io::stdin()
        .lock()
        .lines()
        .map(|x| x.unwrap())
        .collect();
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

    let domains = readlines();

    let count = process_domains(&domains, threads, timeout).await;

    process_result(count, domains.len());
}
