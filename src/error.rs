//! Why a join failed.

use std::fmt;
use std::io;

use crate::handshake::RefuseReason;
use crate::nat::NatSummary;

/// Why joining a game failed. `Display` gives a message fit to show the player.
#[derive(Debug)]
#[non_exhaustive]
pub enum JoinError {
    /// The game runs a version this build cannot play with (decided locally from the listing).
    IncompatibleVersion {
        /// This build's version.
        ours: String,
        /// The host's.
        theirs: String,
    },
    /// The listing says the host is not taking players now (decided locally).
    NotJoinable,
    /// The host refused.
    Refused(RefuseReason),
    /// No relay took the join request; why, per relay.
    RelaysUnavailable(String),
    /// The host never answered the join request.
    HostNotResponding,
    /// Both sides knew each other's addresses, but no path between them worked. The host was
    /// told, so it can suggest a relay to its player.
    NoRoute {
        /// The host's addresses that were tried.
        tried: usize,
        /// Both routers give each destination a port of its own: only a TURN relay on the
        /// host's side can connect the two.
        needs_relay: bool,
        /// This side's router.
        ours: Option<NatSummary>,
        /// The host's router, as it said.
        host: Option<NatSummary>,
    },
    /// The socket failed.
    Io(io::Error),
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinError::IncompatibleVersion { ours, theirs } => write!(
                f,
                "the host runs version {theirs} and you run {ours}; both need compatible versions"
            ),
            JoinError::Refused(RefuseReason::IncompatibleVersion { host_version }) => write!(
                f,
                "the host runs version {host_version}, which does not accept yours"
            ),
            JoinError::NotJoinable | JoinError::Refused(RefuseReason::NotAccepting) => {
                write!(f, "the host is not taking players right now")
            }
            JoinError::Refused(RefuseReason::Busy) => write!(
                f,
                "the host is busy with other players joining; try again in a moment"
            ),
            JoinError::RelaysUnavailable(why) => write!(
                f,
                "could not reach any matchmaking relay; check the internet connection ({why})"
            ),
            JoinError::HostNotResponding => {
                write!(f, "the host did not answer; the game may have closed")
            }
            JoinError::NoRoute {
                tried, needs_relay, ..
            } => {
                write!(f, "no network path to the host worked ({tried} tried); ")?;
                if *needs_relay {
                    write!(
                        f,
                        "both routers block hole punching, so the host needs to set up a relay"
                    )
                } else {
                    write!(
                        f,
                        "the host can set up a relay, turn on UPnP or forward their UDP port"
                    )
                }
            }
            JoinError::Io(e) => write!(f, "network error: {e}"),
        }
    }
}

impl std::error::Error for JoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JoinError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for JoinError {
    fn from(e: io::Error) -> Self {
        JoinError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_errors_are_the_source() {
        use std::error::Error;
        let e = JoinError::from(io::Error::other("boom"));
        assert_eq!(e.source().unwrap().to_string(), "boom");
        assert!(JoinError::HostNotResponding.source().is_none());
    }

    #[test]
    fn no_route_message_reads_as_one_line() {
        let e = JoinError::NoRoute {
            tried: 3,
            needs_relay: true,
            ours: None,
            host: None,
        };
        assert_eq!(
            e.to_string(),
            "no network path to the host worked (3 tried); both routers block hole punching, so \
             the host needs to set up a relay"
        );
    }
}
