use std::fmt;
use std::io;

use crate::handshake::RefuseReason;

/// Why joining a game failed. `Display` gives a message fit to show the player.
#[derive(Debug)]
pub enum JoinError {
    /// The game runs a version this build cannot play with (decided locally from the listing).
    IncompatibleVersion { ours: String, theirs: String },
    /// The listing says the host is not taking players now (decided locally).
    NotJoinable,
    /// The host refused.
    Refused(RefuseReason),
    /// No relay took the join request.
    RelaysUnavailable(String),
    /// The host never answered the join request.
    HostNotResponding,
    /// Both sides knew each other's addresses, but no path between them worked.
    NoRoute {
        /// The host's addresses that were tried.
        tried: usize,
        /// This side's router maps every destination to a different port, which defeats hole
        /// punching unless the host's port is open.
        symmetric_nat: bool,
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
                tried,
                symmetric_nat,
            } => {
                write!(
                    f,
                    "no network path to the host worked ({tried} tried); the host can turn on \
                     UPnP or forward their UDP port"
                )?;
                if *symmetric_nat {
                    write!(f, " (your router's symmetric NAT blocks hole punching)")?;
                }
                Ok(())
            }
            JoinError::Io(e) => write!(f, "network error: {e}"),
        }
    }
}

impl std::error::Error for JoinError {}

impl From<io::Error> for JoinError {
    fn from(e: io::Error) -> Self {
        JoinError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_route_message_reads_as_one_line() {
        let e = JoinError::NoRoute {
            tried: 3,
            symmetric_nat: true,
        };
        assert_eq!(
            e.to_string(),
            "no network path to the host worked (3 tried); the host can turn on UPnP or forward \
             their UDP port (your router's symmetric NAT blocks hole punching)"
        );
    }
}
