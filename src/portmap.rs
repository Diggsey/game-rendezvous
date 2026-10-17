//! Asking the router to forward a host's port: UPnP IGD, and PCP with NAT-PMP as its fallback.
//!
//! Both are tried at once, since a router may speak either. Every mapping made is renewed while
//! the host runs and removed when it stops; the lease is short, so a host that crashes leaves a
//! mapping behind for minutes at most (unless the router only allows permanent UPnP leases).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::time::Duration;

use crab_nat::{InternetProtocol, PortMapping, PortMappingOptions, PortMappingType, TimeoutConfig};
use igd_next::aio::tokio::{Tokio, search_gateway};
use igd_next::{AddAnyPortError, AddPortError, PortMappingProtocol, SearchOptions};
use tokio::sync::oneshot;

use crate::signal::Sink;
use tracing::{debug, info};

/// The lease asked for, renewed at half-time.
const LEASE: Duration = Duration::from_secs(600);
/// How long to look for a gateway.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(3);

/// The protocol a router was asked to forward a port with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PortMapMethod {
    /// UPnP Internet Gateway Device.
    Upnp,
    /// NAT Port Mapping Protocol (RFC 6886).
    NatPmp,
    /// Port Control Protocol (RFC 6887).
    Pcp,
}

impl fmt::Display for PortMapMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PortMapMethod::Upnp => "UPnP",
            PortMapMethod::NatPmp => "NAT-PMP",
            PortMapMethod::Pcp => "PCP",
        })
    }
}

/// A port mapping made (or not) for a host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortMapEvent {
    /// The router forwards `external_port` to the host's socket. `external_ip` is the router's
    /// public address when the protocol tells it.
    Mapped {
        external_ip: Option<IpAddr>,
        external_port: u16,
        method: PortMapMethod,
    },
    /// No router opened the port; the reasons per method.
    Failed(String),
}

enum Mapping {
    Upnp {
        gateway: igd_next::aio::Gateway<Tokio>,
        external_port: u16,
        local: SocketAddr,
        lease: u32,
    },
    Pcp(PortMapping),
}

impl Mapping {
    fn method(&self) -> PortMapMethod {
        match self {
            Mapping::Upnp { .. } => PortMapMethod::Upnp,
            Mapping::Pcp(m) => match m.mapping_type() {
                PortMappingType::NatPmp => PortMapMethod::NatPmp,
                PortMappingType::Pcp { .. } => PortMapMethod::Pcp,
            },
        }
    }

    fn external_port(&self) -> u16 {
        match self {
            Mapping::Upnp { external_port, .. } => *external_port,
            Mapping::Pcp(m) => m.external_port().get(),
        }
    }

    async fn external_ip(&self) -> Option<IpAddr> {
        match self {
            Mapping::Upnp { gateway, .. } => gateway.get_external_ip().await.ok(),
            Mapping::Pcp(m) => match m.mapping_type() {
                PortMappingType::Pcp { external_ip, .. } => Some(external_ip),
                PortMappingType::NatPmp => None,
            },
        }
    }

    async fn renew(&mut self) -> Result<(), String> {
        match self {
            Mapping::Upnp {
                gateway,
                external_port,
                local,
                lease,
            } => gateway
                .add_port(
                    PortMappingProtocol::UDP,
                    *external_port,
                    *local,
                    *lease,
                    "game_rendezvous",
                )
                .await
                .map_err(|e| e.to_string()),
            Mapping::Pcp(m) => m.renew().await.map_err(|e| e.to_string()),
        }
    }

    async fn remove(self) {
        let method = self.method();
        let result = match self {
            Mapping::Upnp {
                gateway,
                external_port,
                ..
            } => gateway
                .remove_port(PortMappingProtocol::UDP, external_port)
                .await
                .map_err(|e| e.to_string()),
            Mapping::Pcp(m) => m.try_drop().await.map_err(|(e, _)| e.to_string()),
        };
        match result {
            Ok(()) => info!("removed the {method} port mapping"),
            Err(e) => debug!("could not remove the {method} port mapping: {e}"),
        }
    }
}

/// The default interface's IPv4 address and its gateway.
fn default_route() -> Option<(Ipv4Addr, Ipv4Addr)> {
    let iface = netdev::get_default_interface().ok()?;
    let local = iface.ipv4.first()?.addr();
    let gateway = *iface.gateway?.ipv4.first()?;
    Some((local, gateway))
}

async fn map_upnp(local: SocketAddr) -> Result<Mapping, String> {
    let IpAddr::V4(local_ip) = local.ip() else {
        return Err("UPnP: no IPv4 address".into());
    };
    let mut options = SearchOptions::default();
    options.bind_addr = SocketAddr::from((local_ip, 0));
    options.timeout = Some(SEARCH_TIMEOUT);
    options.single_search_timeout = Some(SEARCH_TIMEOUT);
    let gateway = search_gateway(options)
        .await
        .map_err(|e| format!("UPnP: {e}"))?;
    let mut lease = LEASE.as_secs() as u32;
    let desc = "game_rendezvous";
    // The same external port as the local one if free, otherwise any.
    let mut result = gateway
        .add_port(PortMappingProtocol::UDP, local.port(), local, lease, desc)
        .await;
    if let Err(AddPortError::OnlyPermanentLeasesSupported) = result {
        lease = 0;
        result = gateway
            .add_port(PortMappingProtocol::UDP, local.port(), local, lease, desc)
            .await;
    }
    let external_port = match result {
        Ok(()) => local.port(),
        Err(_) => {
            let mut any = gateway
                .add_any_port(PortMappingProtocol::UDP, local, lease, desc)
                .await;
            if let Err(AddAnyPortError::OnlyPermanentLeasesSupported) = any {
                lease = 0;
                any = gateway
                    .add_any_port(PortMappingProtocol::UDP, local, lease, desc)
                    .await;
            }
            any.map_err(|e| format!("UPnP: {e}"))?
        }
    };
    Ok(Mapping::Upnp {
        gateway,
        external_port,
        local,
        lease,
    })
}

async fn map_pcp(local: SocketAddr, gateway: Ipv4Addr) -> Result<Mapping, String> {
    let port = NonZeroU16::new(local.port()).ok_or("PCP: port 0")?;
    let options = PortMappingOptions {
        external_port: Some(port),
        lifetime_seconds: Some(LEASE.as_secs() as u32),
        timeout_config: Some(TimeoutConfig {
            initial_timeout: Duration::from_millis(250),
            max_retries: 3,
            max_retry_timeout: Some(Duration::from_secs(1)),
        }),
    };
    PortMapping::new(
        gateway.into(),
        local.ip(),
        InternetProtocol::Udp,
        port,
        options,
    )
    .await
    .map(Mapping::Pcp)
    .map_err(|e| format!("PCP/NAT-PMP: {e}"))
}

/// Maps `port` on the router, reports to `events`, renews the mapping until `stop` fires (or
/// its sender is dropped), then removes it.
/// Maps `port` on the router, reports to `events`, renews the mapping until `stop` fires (or
/// its sender is dropped), then removes it.
pub(crate) async fn run(port: u16, events: Sink<PortMapEvent>, mut stop: oneshot::Receiver<()>) {
    let Some((local_ip, gateway)) = tokio::task::spawn_blocking(default_route)
        .await
        .ok()
        .flatten()
    else {
        let _ = events.send(PortMapEvent::Failed("no default IPv4 gateway".into()));
        return;
    };
    let local = SocketAddr::from((local_ip, port));
    let (upnp, pcp) = tokio::join!(map_upnp(local), map_pcp(local, gateway));
    let mut mappings = match successes([pcp, upnp]) {
        Ok(m) => m,
        Err(why) => {
            debug!("no port mapping: {why}");
            let _ = events.send(PortMapEvent::Failed(why));
            return;
        }
    };
    report(&mappings[0], port, &events).await;
    loop {
        tokio::select! {
            _ = &mut stop => break,
            () = tokio::time::sleep(LEASE / 2) => {
                for m in &mut mappings {
                    if let Err(e) = m.renew().await {
                        debug!("could not renew the {} port mapping: {e}", m.method());
                    }
                }
            }
        }
    }
    for m in mappings {
        m.remove().await;
    }
}

/// Tells the host about `mapping`.
async fn report(mapping: &Mapping, port: u16, events: &Sink<PortMapEvent>) {
    let external_ip = mapping.external_ip().await;
    info!(
        "{} mapped port {} to {:?}:{}",
        mapping.method(),
        port,
        external_ip,
        mapping.external_port()
    );
    let _ = events.send(PortMapEvent::Mapped {
        external_ip,
        external_port: mapping.external_port(),
        method: mapping.method(),
    });
}

/// The mappings that were made, in the order tried, or every reason none was.
///
/// All of them are kept, renewed and removed at the end, rather than the extras being removed
/// at once: routers running miniupnpd serve UPnP, NAT-PMP and PCP from one table of redirects,
/// so two protocols mapping the same port make one rule, and removing either mapping removes
/// the rule the other one reported. Keeping both costs a renewal each.
fn successes<T, const N: usize>(results: [Result<T, String>; N]) -> Result<Vec<T>, String> {
    let mut made = Vec::new();
    let mut errors = Vec::new();
    for r in results {
        match r {
            Ok(m) => made.push(m),
            Err(e) => errors.push(e),
        }
    }
    if made.is_empty() {
        Err(errors.join("; "))
    } else {
        Ok(made)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mapping_made_is_kept_in_order() {
        let both: [Result<&str, String>; 2] = [Ok("pcp"), Ok("upnp")];
        assert_eq!(successes(both), Ok(vec!["pcp", "upnp"]));
        let one: [Result<&str, String>; 2] = [Err("PCP: no".into()), Ok("upnp")];
        assert_eq!(successes(one), Ok(vec!["upnp"]));
        let none: [Result<&str, String>; 2] = [Err("PCP: no".into()), Err("UPnP: no".into())];
        assert_eq!(successes(none), Err("PCP: no; UPnP: no".into()));
    }

    #[test]
    fn methods_print_as_their_usual_names() {
        let names: Vec<String> = [PortMapMethod::Upnp, PortMapMethod::NatPmp, PortMapMethod::Pcp]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["UPnP", "NAT-PMP", "PCP"]);
    }
}
