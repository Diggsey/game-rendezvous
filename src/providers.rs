//! TURN relay providers a host's player can sign up with: the list a game shows in its relay
//! settings, and how each one's credentials become a [`TurnConfig`].
//!
//! THE LIST IS [`DEFAULT_RELAY_PROVIDERS`], below. Every fact in it (servers, endpoints, free
//! tiers) comes from the provider's own pages, noted with the date they were checked. Notes
//! shown to players claim nothing a provider's pages do not state (e.g. that no card is
//! needed). Check them again when updating the list.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::config::{TurnConfig, TurnServer};

/// An HTTP method for a provider's credential API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HttpMethod {
    /// GET.
    Get,
    /// POST.
    Post,
}

/// A value the player enters for a provider, e.g. a username or an API key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RelayField {
    /// The key it is stored and looked up under, e.g. `"username"`.
    pub key: &'static str,
    /// What to call it on screen, e.g. `"Username"`.
    pub label: &'static str,
    /// It is a secret: hide it on screen.
    pub secret: bool,
}

impl RelayField {
    /// A field.
    #[must_use]
    pub const fn new(key: &'static str, label: &'static str, secret: bool) -> RelayField {
        RelayField { key, label, secret }
    }
}

/// The fields of a server entered by hand.
const SERVER_FIELD: RelayField = RelayField::new("server", "Server (host:port)", false);
/// A long-term credential's fields.
const LOGIN_FIELDS: [RelayField; 2] = [
    RelayField::new("username", "Username", false),
    RelayField::new("password", "Password", true),
];

/// A provider's API for short-lived credentials: one HTTPS request answered with WebRTC's
/// `iceServers` (a JSON array of `{urls, username, credential}`, alone or as
/// `{"iceServers": [...]}`). `{key}` in the URL and body stands for the player's value for the
/// field `key` (URL-encoded in the URL, JSON-escaped in the body).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CredentialApi {
    /// The method.
    pub method: HttpMethod,
    /// The URL template; it must be `https://`.
    pub url: &'static str,
    /// The field whose value goes in an `Authorization: Bearer` header, if any.
    pub bearer: Option<&'static str>,
    /// The JSON body template, if any.
    pub body: Option<&'static str>,
    /// What the player enters.
    pub fields: &'static [RelayField],
    /// How long the credentials last: they are fetched again before then (between games).
    pub lifetime: Duration,
}

impl CredentialApi {
    /// An API at the `url` template asking the player for `fields`; no header, no body, and
    /// credentials that last a day.
    #[must_use]
    pub const fn new(method: HttpMethod, url: &'static str, fields: &'static [RelayField]) -> Self {
        CredentialApi {
            method,
            url,
            bearer: None,
            body: None,
            fields,
            lifetime: Duration::from_secs(24 * 3600),
        }
    }

    /// Sends the value of the field `key` as a bearer token.
    #[must_use]
    pub const fn bearer(mut self, key: &'static str) -> Self {
        self.bearer = Some(key);
        self
    }

    /// Sends this JSON body template.
    #[must_use]
    pub const fn body(mut self, body: &'static str) -> Self {
        self.body = Some(body);
        self
    }

    /// The credentials last this long.
    #[must_use]
    pub const fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }
}

/// How a provider's credentials are had.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RelayCredentials {
    /// A username and password the player copies from the provider's dashboard, for `server`
    /// (`host:port`), or for a server the player enters too when `None`.
    Login {
        /// The server, if the provider has a fixed one.
        server: Option<&'static str>,
    },
    /// Credentials fetched from the provider's API, with values the player copies from its
    /// dashboard. Needs the `relay-api` feature.
    Api(CredentialApi),
}

/// A TURN relay provider, as a game's relay settings list it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RelayProvider {
    /// Identifies it in saved settings, e.g. `"cloudflare"`.
    pub id: &'static str,
    /// Its name, as players see it.
    pub name: &'static str,
    /// Where to sign up (empty for a server of one's own).
    pub signup_url: &'static str,
    /// A line or two for players: the free allowance, where to find the credentials.
    pub notes: &'static str,
    /// How its credentials are had.
    pub credentials: RelayCredentials,
}

impl RelayProvider {
    /// A provider whose dashboard gives a username and password, for `server` (or for a
    /// server the player enters, if `None`).
    #[must_use]
    pub const fn login(
        id: &'static str,
        name: &'static str,
        signup_url: &'static str,
        notes: &'static str,
        server: Option<&'static str>,
    ) -> RelayProvider {
        RelayProvider {
            id,
            name,
            signup_url,
            notes,
            credentials: RelayCredentials::Login { server },
        }
    }

    /// A provider whose credentials come from its API.
    #[must_use]
    pub const fn api(
        id: &'static str,
        name: &'static str,
        signup_url: &'static str,
        notes: &'static str,
        api: CredentialApi,
    ) -> RelayProvider {
        RelayProvider {
            id,
            name,
            signup_url,
            notes,
            credentials: RelayCredentials::Api(api),
        }
    }

    /// What the player enters for it, in order.
    #[must_use]
    pub fn fields(&self) -> Vec<RelayField> {
        match self.credentials {
            RelayCredentials::Login { server: Some(_) } => LOGIN_FIELDS.to_vec(),
            RelayCredentials::Login { server: None } => {
                std::iter::once(SERVER_FIELD).chain(LOGIN_FIELDS).collect()
            }
            RelayCredentials::Api(api) => api.fields.to_vec(),
        }
    }

    /// The relay configuration for the player's `values` (by [`RelayField::key`]).
    ///
    /// # Errors
    ///
    /// If a value is missing or empty (the message names the field), or the provider needs the
    /// `relay-api` feature.
    pub fn config(&self, values: &BTreeMap<String, String>) -> Result<TurnConfig, String> {
        for f in self.fields() {
            if values.get(f.key).is_none_or(|v| v.trim().is_empty()) {
                return Err(format!("{} is missing", f.label));
            }
        }
        let value = |k: &str| {
            values
                .get(k)
                .map_or(String::new(), |v| v.trim().to_string())
        };
        match self.credentials {
            RelayCredentials::Login { server } => Ok(TurnConfig::Static(TurnServer::new(
                server.map_or_else(|| value("server"), str::to_string),
                value("username"),
                value("password"),
            ))),
            RelayCredentials::Api(api) => api_config(api, values),
        }
    }
}

/// The configuration fetching credentials from `api`.
#[cfg(feature = "relay-api")]
#[allow(clippy::unnecessary_wraps, reason = "fails without the feature")]
fn api_config(api: CredentialApi, values: &BTreeMap<String, String>) -> Result<TurnConfig, String> {
    let values = values.clone();
    Ok(TurnConfig::provider(move || {
        let values = values.clone();
        Box::pin(async move { crate::fetch::credentials(&api, &values).await })
    }))
}

/// Without the `relay-api` feature, API providers cannot be used.
#[cfg(not(feature = "relay-api"))]
fn api_config(_: CredentialApi, _: &BTreeMap<String, String>) -> Result<TurnConfig, String> {
    Err("this game was built without relay API support (the `relay-api` feature)".into())
}

/// A TURN server of the player's own (coturn, say): any server, username and password.
pub const CUSTOM_RELAY: RelayProvider = RelayProvider::login(
    "custom",
    "Your own server",
    "",
    "Any TURN server that relays UDP with a username and password, such as coturn.",
    None,
);

/// The relay providers known to have a free tier, for a game's relay settings. A game may show
/// its own list instead; [`CUSTOM_RELAY`] covers any other server.
///
/// Checked against each provider's own pages on 2026-10-17; see the comment on each entry.
pub const DEFAULT_RELAY_PROVIDERS: &[RelayProvider] = &[
    // ExpressTURN. Checked 2026-10-17:
    // - Free plan "limited to 1000 GB of traffic per month", "supports TCP and UDP on port
    //   3478"; sign-up form at #signup; Premium unlocks "all server locations and Secret Key
    //   authentication": https://www.expressturn.com/
    // - Free tier server `turn:free.expressturn.com:3478`, "the free tier only issues a
    //   username and password": https://www.expressturn.com/blog/jitsi-meet-turn-server-setup
    //   and https://www.expressturn.com/blog/nextcloud-talk-turn-server-setup
    // - Not stated anywhere: whether the free plan needs a card.
    RelayProvider::login(
        "expressturn",
        "ExpressTURN",
        "https://www.expressturn.com/#signup",
        "Free plan: 1,000 GB of relay traffic a month. Copy the username and password from \
         your ExpressTURN dashboard.",
        Some("free.expressturn.com:3478"),
    ),
    // Cloudflare Realtime TURN. Checked 2026-10-17:
    // - "TURN over UDP | turn.cloudflare.com | 3478/udp | alternate 443/udp":
    //   https://developers.cloudflare.com/realtime/turn/
    // - Credentials only from the API: POST
    //   https://rtc.live.cloudflare.com/v1/turn/keys/$TURN_KEY_ID/credentials/generate-ice-servers
    //   with "Authorization: Bearer $TURN_KEY_API_TOKEN" and {"ttl": 86400}, answered with
    //   {"iceServers": [...]}; TURN keys are made in the dashboard:
    //   https://developers.cloudflare.com/realtime/turn/generate-credentials/
    // - Credentials last "up to 48 hours"; "a free tier of 1,000 GB before any charges
    //   start": https://developers.cloudflare.com/realtime/turn/faq/
    // - Not stated anywhere: whether the free tier needs a card.
    RelayProvider::api(
        "cloudflare",
        "Cloudflare Realtime TURN",
        "https://dash.cloudflare.com/?to=/:account/calls",
        "The first 1,000 GB of relay traffic each month are free. Create a TURN key in the \
         Cloudflare dashboard (Realtime), then copy its key ID and API token.",
        CredentialApi::new(
            HttpMethod::Post,
            "https://rtc.live.cloudflare.com/v1/turn/keys/{key_id}/credentials/generate-ice-servers",
            &[
                RelayField::new("key_id", "TURN key ID", false),
                RelayField::new("api_token", "API token", true),
            ],
        )
        .bearer("api_token")
        .body(r#"{"ttl": 172800}"#)
        .lifetime(Duration::from_secs(172_800)),
    ),
    // Metered TURN. Checked 2026-10-17:
    // - Sign-up: https://dashboard.metered.ca/signup?tool=stunturn, from
    //   https://www.metered.ca/stun-turn
    // - Free plan "500 MB monthly TURN usage (ingress + egress)", "No credit card required":
    //   https://www.metered.ca/pricing
    // - GET https://{app_name}.metered.live/api/v1/turn/credentials?apiKey={api_key}, answered
    //   with an array of {urls, username, credential}; the API key is made with each
    //   credential: https://www.metered.ca/docs/turn-rest-api/get-credential
    // - "A new credential can take up to 2 minutes to propagate"; credentials expire only if
    //   made with an expiry: https://www.metered.ca/docs/llms-turn-server.txt
    // - The free plan's server is standard.relay.metered.ca, on ports 80 and 443:
    //   https://www.metered.ca/docs/turnserver-guides/turnserver-regions/ (the API's answer
    //   names it, so it is not fixed here).
    RelayProvider::api(
        "metered",
        "Metered",
        "https://dashboard.metered.ca/signup?tool=stunturn",
        "Free plan: 500 MB of relay traffic a month, no credit card required. Create a TURN \
         credential in the dashboard, then copy your app name (the part before .metered.live) \
         and the credential's API key. A new credential takes up to 2 minutes to work.",
        CredentialApi::new(
            HttpMethod::Get,
            "https://{app_name}.metered.live/api/v1/turn/credentials?apiKey={api_key}",
            &[
                RelayField::new("app_name", "App name", false),
                RelayField::new("api_key", "API key", true),
            ],
        )
        // Fetched again daily, though they last until deleted.
        .lifetime(Duration::from_secs(24 * 3600)),
    ),
];

/// The provider with this [`id`](RelayProvider::id) among the defaults and [`CUSTOM_RELAY`].
#[must_use]
pub fn relay_provider(id: &str) -> Option<&'static RelayProvider> {
    DEFAULT_RELAY_PROVIDERS
        .iter()
        .chain(std::iter::once(&CUSTOM_RELAY))
        .find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn every_provider_is_complete_and_unique() {
        let mut ids: Vec<&str> = DEFAULT_RELAY_PROVIDERS.iter().map(|p| p.id).collect();
        ids.push(CUSTOM_RELAY.id);
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "ids are unique");
        for p in DEFAULT_RELAY_PROVIDERS {
            assert!(p.signup_url.starts_with("https://"), "{}", p.id);
            assert!(!p.notes.is_empty() && !p.fields().is_empty(), "{}", p.id);
            if let RelayCredentials::Api(api) = p.credentials {
                assert!(api.url.starts_with("https://"), "{}", p.id);
                for f in api.fields {
                    let used = api.url.contains(&format!("{{{}}}", f.key))
                        || api.bearer == Some(f.key)
                        || api
                            .body
                            .is_some_and(|b| b.contains(&format!("{{{}}}", f.key)));
                    assert!(used, "{}: field {} is used", p.id, f.key);
                }
            }
        }
    }

    #[test]
    fn logins_become_static_configs() {
        let express = relay_provider("expressturn").unwrap();
        let fields: Vec<&str> = express.fields().iter().map(|f| f.key).collect();
        assert_eq!(fields, ["username", "password"]);
        let TurnConfig::Static(s) = express
            .config(&values(&[("username", " ann "), ("password", "pw")]))
            .unwrap()
        else {
            panic!("a static config")
        };
        assert_eq!(
            (s.address.as_str(), s.username.as_str(), s.password.as_str()),
            ("free.expressturn.com:3478", "ann", "pw")
        );
        let custom = relay_provider("custom").unwrap();
        assert_eq!(custom.fields()[0].key, "server");
        assert_eq!(
            custom
                .config(&values(&[("username", "a"), ("password", "b")]))
                .err(),
            Some("Server (host:port) is missing".into())
        );
    }
}
