#[macro_use] extern crate rocket;

use rand::prelude::*;
use std::str::FromStr;
use trust_dns_client::proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_client::client::ClientHandle;

#[derive(Debug, PartialEq, FromFormField, Copy, Clone)]
enum Protocol {
    #[field(value = "udp")]
    UDP,
    #[field(value = "tcp")]
    TCP
}

#[derive(Debug, PartialEq, FromFormField, Copy, Clone)]
enum ProbeType {
    #[field(value = "soa")]
    SOA,
    #[field(value = "secondary")]
    Secondary
}

struct DnsProbeResult {
    started: std::time::Duration,
    valid_domain: bool,
    ip_proto: u8,
    soa: Option<u32>,
}


async fn run_dns_probe(server: &str, domain: &str, proto: Protocol) -> DnsProbeResult {
    let start = std::time::Instant::now();

    let domain = match trust_dns_client::rr::Name::from_str(domain) {
        Ok(name) => name,
        Err(_) => return DnsProbeResult {
            started: start.elapsed(),
            valid_domain: false,
            ip_proto: 0,
            soa: None,
        }
    };

    let server_address: std::net::SocketAddr = match tokio::net::lookup_host(server).await {
        Ok(a) => {
            let mut rng = thread_rng();
            match a.choose(&mut rng) {
                Some(addr) => addr,
                _ => return DnsProbeResult {
                    started: start.elapsed(),
                    valid_domain: true,
                    ip_proto: 0,
                    soa: None,
                }
            }
        },
        _ => return DnsProbeResult {
            started: start.elapsed(),
            valid_domain: true,
            ip_proto: 0,
            soa: None,
        }
    };

    let ip_proto = if server_address.is_ipv4() {
        4
    } else {
        6
    };

    let mut client = match proto {
        Protocol::UDP => {
            let stream = trust_dns_client::udp::UdpClientStream::<
                tokio::net::UdpSocket
            >::new(server_address);
            match trust_dns_client::client::AsyncClient::connect(stream).await {
                Ok((conn, handle)) => {
                    tokio::spawn(handle);
                    conn
                },
                Err(_) => return DnsProbeResult {
                    started: start.elapsed(),
                    valid_domain: true,
                    ip_proto,
                    soa: None,
                }
            }
        },
        Protocol::TCP => {
            let (stream, handle) = trust_dns_client::tcp::TcpClientStream::<
                AsyncIoTokioAsStd<tokio::net::TcpStream>
            >::new(server_address);
            match trust_dns_client::client::AsyncClient::with_timeout(
                stream, handle, std::time::Duration::from_secs(5), None
            ).await {
                Ok((conn, handle)) => {
                    tokio::spawn(handle);
                    conn
                },
                Err(_) => return DnsProbeResult {
                    started: start.elapsed(),
                    valid_domain: true,
                    ip_proto,
                    soa: None,
                }
            }
        },
    };

    let response = match client.query(
        domain,
        trust_dns_client::rr::DNSClass::IN,
        trust_dns_client::rr::RecordType::SOA,
    ).await {
        Ok(response) => response,
        Err(_) => return DnsProbeResult {
            started: start.elapsed(),
            valid_domain: true,
            ip_proto,
            soa: None,
        }
    };

    if !response.contains_answer() {
        return DnsProbeResult {
            started: start.elapsed(),
            valid_domain: true,
            ip_proto,
            soa: None,
        }
    }

    let answers: Vec<_> = response.answers().iter().collect();
    if answers.len() != 1 {
        return DnsProbeResult {
            started: start.elapsed(),
            valid_domain: true,
            ip_proto,
            soa: None,
        }
    }

    let soa = match answers[0].data() {
        Some(trust_dns_client::rr::RData::SOA(soa)) => Some(soa.serial()),
        _ => None,
    };

    DnsProbeResult {
        started: start.elapsed(),
        valid_domain: true,
        ip_proto,
        soa,
    }
}

async fn probe_soa(host: &str, domain: &str, proto: Protocol) -> String {
    let result = run_dns_probe(host, domain, proto).await;

    let mut out = String::new();

    out.push_str(&format!("probe_duration_seconds {}\n", result.started.as_secs_f64()));
    out.push_str(&format!("probe_valid_domain {}\n", result.valid_domain as u8));
    out.push_str(&format!("probe_ip_protocol {}\n", result.ip_proto));

    if result.soa.is_some() {
        out.push_str(&format!("probe_soa {}\n", result.soa.unwrap()));
        out.push_str("probe_success 1\n");
    } else {
        out.push_str("probe_success 0\n");
    }

    out
}

async fn probe_secondary(primary: &str, secondary: &str, domain: &str, proto: Protocol) -> String {
    let start = std::time::Instant::now();

    let result_primary = run_dns_probe(primary, domain, proto).await;
    let result_secondary = run_dns_probe(secondary, domain, proto).await;

    let mut out = String::new();

    out.push_str(&format!("probe_duration_seconds {}\n", start.elapsed().as_secs_f64()));
    out.push_str(&format!("probe_duration_primary_seconds {}\n", result_primary.started.as_secs_f64()));
    out.push_str(&format!("probe_duration_secondary_seconds {}\n", result_secondary.started.as_secs_f64()));
    out.push_str(&format!("probe_valid_domain {}\n", result_secondary.valid_domain as u8));
    out.push_str(&format!("probe_primary_ip_protocol {}\n", result_primary.ip_proto));
    out.push_str(&format!("probe_secondary_ip_protocol {}\n", result_secondary.ip_proto));

    if result_primary.soa.is_some() {
        out.push_str(&format!("probe_primary_soa {}\n", result_primary.soa.unwrap()));
        out.push_str("probe_primary_success 1\n");
    } else {
        out.push_str("probe_primary_success 0\n");
    }
    if result_secondary.soa.is_some() {
        out.push_str(&format!("probe_secondary_soa {}\n", result_secondary.soa.unwrap()));
        out.push_str("probe_secondary_success 1\n");
    } else {
        out.push_str("probe_secondary_success 0\n");
    }

    if result_primary.soa.is_some() && result_secondary.soa.is_some() {
        if result_primary.soa.unwrap() == result_secondary.soa.unwrap() {
            out.push_str("probe_soa_match 1\n");
        } else {
            out.push_str("probe_soa_match 0\n");
        }
    } else {
        out.push_str("probe_soa_match 0\n");
    }

    out
}

#[get("/probe?<type>&<host>&<primary>&<domain>&<proto>")]
async fn probe(r#type: ProbeType, host: &str, primary: Option<&str>, domain: &str, proto: Protocol) -> String {
    match r#type {
        ProbeType::SOA => probe_soa(host, domain, proto).await,
        ProbeType::Secondary => probe_secondary(primary.unwrap_or_default(), host, domain, proto).await,
    }
}

#[launch]
fn rocket() -> _ {
    pretty_env_logger::init();

    rocket::build().mount("/", routes![probe])
}