//! Asking the router to forward a host's port (UPnP IGD, NAT-PMP or PCP): what a host hears of
//! it. The asking is in [`router`], with the `port-mapping` feature.

use std::fmt;
use std::net::IpAddr;

use tokio::sync::oneshot;

use crate::worker::Sink;

#[cfg(feature = "port-mapping")]
mod router;

/// The protocol a router was asked to forward a port with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// The router stopped forwarding the port: renewing every mapping failed, for these
    /// reasons. A later renewal that works reports [`Mapped`](PortMapEvent::Mapped) again.
    Lost(String),
}

/// Maps `port` on the router, reports to `events`, renews the mapping until `stop` fires (or
/// its sender is dropped), then removes it.
#[cfg(feature = "port-mapping")]
pub(crate) async fn run(port: u16, events: Sink<PortMapEvent>, stop: oneshot::Receiver<()>) {
    router::run(port, events, stop).await;
}

/// Without the `port-mapping` feature: reports that no port was mapped.
#[cfg(not(feature = "port-mapping"))]
pub(crate) async fn run(_port: u16, events: Sink<PortMapEvent>, _stop: oneshot::Receiver<()>) {
    let why = "built without port mapping (the `port-mapping` feature)";
    let _ = events.send(PortMapEvent::Failed(why.into()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods_print_as_their_usual_names() {
        let names: Vec<String> = [PortMapMethod::Upnp, PortMapMethod::NatPmp, PortMapMethod::Pcp]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["UPnP", "NAT-PMP", "PCP"]);
    }
}
