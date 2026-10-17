//! Fetching TURN credentials from a provider's API (see [`CredentialApi`]): one HTTPS request,
//! answered with WebRTC's `iceServers`.
//!
//! The request is plain HTTP/1.1 over rustls, which the Nostr client already brings in: an
//! HTTP client crate would add more than this needs. Credentials are kept until shortly before
//! they expire, so hosting again does not ask the provider again.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{self, pki_types::ServerName};

use crate::config::TurnServer;
use crate::providers::{CredentialApi, HttpMethod};

/// The most of an answer read.
const MAX_RESPONSE: usize = 256 * 1024;
/// How long a request may take.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Credentials are fetched again once less than this, or a tenth of their life, remains.
const MARGIN: Duration = Duration::from_secs(3600);

/// Credentials fetched, by request, with when to fetch again.
type Cache = Mutex<BTreeMap<String, (TurnServer, Instant)>>;

/// Credentials for `api` with the player's `values`: kept ones while fresh, else fetched.
pub(crate) async fn credentials(
    api: &CredentialApi,
    values: &BTreeMap<String, String>,
) -> Result<TurnServer, String> {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Cache::default);
    let request = Request::new(api, values)?;
    let key = format!(
        "{}\n{}\n{:?}\n{:?}",
        request.host, request.path, request.bearer, request.body
    );
    if let Some((server, until)) = cache.lock().unwrap().get(&key)
        && Instant::now() < *until
    {
        return Ok(server.clone());
    }
    let body = tokio::time::timeout(TIMEOUT, request.send())
        .await
        .map_err(|_| format!("{} did not answer", request.host))??;
    let server = ice_servers(&body).map_err(|why| format!("{}: {why}", request.host))?;
    let margin = MARGIN.min(api.lifetime / 10);
    cache.lock().unwrap().insert(
        key,
        (
            server.clone(),
            Instant::now() + api.lifetime.saturating_sub(margin),
        ),
    );
    Ok(server)
}

/// An HTTPS request, filled in.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    /// GET or POST.
    method: HttpMethod,
    /// The host name.
    host: String,
    /// The port.
    port: u16,
    /// The path and query.
    path: String,
    /// A bearer token.
    bearer: Option<String>,
    /// A JSON body.
    body: Option<String>,
}

impl Request {
    /// The request `api` makes with `values`.
    fn new(api: &CredentialApi, values: &BTreeMap<String, String>) -> Result<Request, String> {
        let value = |k: &str| {
            values
                .get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{k} is missing"))
        };
        let mut url = api.url.to_string();
        let mut body = api.body.map(str::to_string);
        for f in api.fields {
            let v = value(f.key)?;
            let slot = format!("{{{}}}", f.key);
            url = url.replace(&slot, &url_encode(&v));
            body = body.map(|b| {
                let quoted = serde_json::to_string(&v).unwrap_or_default();
                b.replace(&slot, &quoted[1..quoted.len() - 1])
            });
        }
        let rest = url
            .strip_prefix("https://")
            .ok_or("the provider's URL is not https://")?;
        let (authority, path) = rest.find('/').map_or((rest, "/"), |i| rest.split_at(i));
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| "bad port in the provider's URL")?),
            None => (authority, 443),
        };
        let name_char = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
        if host.is_empty() || !host.chars().all(name_char) {
            return Err(format!("not a host name: {host} (check what was entered)"));
        }
        Ok(Request {
            method: api.method,
            host: host.to_ascii_lowercase(),
            port,
            path: path.to_string(),
            bearer: api.bearer.map(value).transpose()?,
            body,
        })
    }

    /// The request's bytes.
    fn encode(&self) -> String {
        let method = match self.method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        };
        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\
             User-Agent: game_rendezvous\r\n",
            self.path, self.host
        );
        if let Some(token) = &self.bearer {
            let _ = write!(head, "Authorization: Bearer {token}\r\n");
        }
        let body = self.body.as_deref().unwrap_or("");
        if self.method == HttpMethod::Post {
            let _ = write!(
                head,
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            );
        }
        head + "\r\n" + body
    }

    /// Sends it, and returns the body of a successful answer.
    async fn send(&self) -> Result<Vec<u8>, String> {
        let unreachable = |e: std::io::Error| format!("cannot reach {}: {e}", self.host);
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(unreachable)?;
        let name = ServerName::try_from(self.host.clone()).map_err(|e| e.to_string())?;
        let mut tls = TlsConnector::from(tls_config()?)
            .connect(name, tcp)
            .await
            .map_err(unreachable)?;
        tls.write_all(self.encode().as_bytes())
            .await
            .map_err(unreachable)?;
        let mut response = Vec::new();
        let mut chunk = [0; 8192];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&chunk[..n]),
                // Servers often close without TLS's goodbye; the length tells if all came.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(unreachable(e)),
            }
            if response.len() > MAX_RESPONSE {
                return Err(format!("{} sent too much", self.host));
            }
        }
        parse_response(&response)
    }
}

/// TLS with the Mozilla roots, made once.
fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
}

/// The body of an HTTP/1.1 answer, if it was a success.
fn parse_response(data: &[u8]) -> Result<Vec<u8>, String> {
    let end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("the provider's answer was cut short")?;
    let head = String::from_utf8_lossy(&data[..end]);
    let mut body = &data[end + 4..];
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("the provider's answer is not HTTP")?;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        } else if name == "content-length" {
            let n: usize = value.parse().map_err(|_| "bad Content-Length")?;
            body = body.get(..n).ok_or("the provider's answer was cut short")?;
        }
    }
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    match status {
        200..=299 => Ok(body),
        401 | 403 => Err("the provider refused the key (check what was entered)".into()),
        404 => Err("the provider does not know that key or app (check what was entered)".into()),
        _ => Err(format!(
            "the provider answered {status}: {}",
            String::from_utf8_lossy(&body[..body.len().min(200)])
        )),
    }
}

/// A chunked body, joined.
fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let cut = || "the provider's answer was cut short".to_string();
    let mut out = Vec::new();
    loop {
        let eol = data.windows(2).position(|w| w == b"\r\n").ok_or_else(cut)?;
        let size = String::from_utf8_lossy(&data[..eol]);
        let size = size.split(';').next().unwrap_or("").trim();
        let n = usize::from_str_radix(size, 16).map_err(|_| "bad chunk in the answer")?;
        data = &data[eol + 2..];
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(data.get(..n).ok_or_else(cut)?);
        data = data.get(n + 2..).ok_or_else(cut)?;
    }
}

/// An entry of WebRTC's `iceServers`.
#[derive(Deserialize)]
struct IceServer {
    /// One URL or several.
    urls: Urls,
    /// The username, for TURN.
    #[serde(default)]
    username: Option<String>,
    /// The password, for TURN.
    #[serde(default)]
    credential: Option<String>,
}

/// `urls`: a string or a list.
#[derive(Deserialize)]
#[serde(untagged)]
enum Urls {
    /// One.
    One(String),
    /// Several.
    Many(Vec<String>),
}

/// `iceServers` alone, or in an object, as one entry or a list.
#[derive(Deserialize)]
#[serde(untagged)]
enum IceServers {
    /// `{"iceServers": ...}`.
    Wrapped {
        /// The servers.
        #[serde(rename = "iceServers")]
        ice_servers: OneOrMany,
    },
    /// The servers alone.
    Bare(OneOrMany),
}

/// One entry or a list.
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    /// One.
    One(IceServer),
    /// Several.
    Many(Vec<IceServer>),
}

/// The first plain-UDP TURN server in an `iceServers` answer.
fn ice_servers(body: &[u8]) -> Result<TurnServer, String> {
    let parsed: IceServers =
        serde_json::from_slice(body).map_err(|_| "the answer is not a list of ICE servers")?;
    let (IceServers::Wrapped { ice_servers: list } | IceServers::Bare(list)) = parsed;
    let list = match list {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(l) => l,
    };
    let mut best: Option<(u8, TurnServer)> = None;
    for s in list {
        let (Some(user), Some(pass)) = (s.username, s.credential) else {
            continue;
        };
        let urls = match s.urls {
            Urls::One(u) => vec![u],
            Urls::Many(u) => u,
        };
        for url in urls {
            // `turn:` only (not `turns:`, TLS), over UDP: explicitly, or by default.
            let Some(rest) = url.strip_prefix("turn:") else {
                continue;
            };
            let transport = rest.split_once("?transport=").map(|(_, t)| t);
            let rank = match transport {
                Some(t) if t.eq_ignore_ascii_case("udp") => 0,
                None => 1,
                Some(_) => continue,
            };
            // Port 53 is DNS's, and often filtered; it comes last.
            let rank = rank
                + if rest.contains(":53?") || rest.ends_with(":53") {
                    2
                } else {
                    0
                };
            if best.as_ref().is_none_or(|(r, _)| rank < *r) {
                best = Some((
                    rank,
                    TurnServer::new(url.clone(), user.clone(), pass.clone()),
                ));
            }
        }
    }
    best.map(|(_, s)| s)
        .ok_or_else(|| "the answer has no UDP TURN server".into())
}

/// `s`, percent-encoded for a URL.
fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::relay_provider;

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn api(id: &str) -> CredentialApi {
        match relay_provider(id).unwrap().credentials {
            crate::providers::RelayCredentials::Api(api) => api,
            crate::providers::RelayCredentials::Login { .. } => panic!("{id} has an API"),
        }
    }

    #[test]
    fn requests_are_filled_in() {
        let r = Request::new(
            &api("cloudflare"),
            &values(&[("key_id", "abc"), ("api_token", "t\"k")]),
        )
        .unwrap();
        assert_eq!(r.host, "rtc.live.cloudflare.com");
        assert_eq!(r.path, "/v1/turn/keys/abc/credentials/generate-ice-servers");
        assert_eq!(r.bearer.as_deref(), Some("t\"k"));
        let text = r.encode();
        assert!(text.starts_with("POST /v1/turn/keys/abc/"), "{text}");
        assert!(text.contains("Authorization: Bearer t\"k\r\n"));
        assert!(text.ends_with("\r\n\r\n{\"ttl\": 172800}"));
        assert!(
            Request::new(
                &api("metered"),
                &values(&[("app_name", "my app"), ("api_key", "k")])
            )
            .is_err()
        );
        let r = Request::new(
            &api("metered"),
            &values(&[("app_name", "MyApp"), ("api_key", "k&1")]),
        )
        .unwrap();
        assert_eq!((r.host.as_str(), r.port), ("myapp.metered.live", 443));
        assert_eq!(r.path, "/api/v1/turn/credentials?apiKey=k%261");
        assert!(
            r.encode()
                .starts_with("GET /api/v1/turn/credentials?apiKey=k%261 HTTP/1.1\r\n")
        );
        assert!(Request::new(&api("metered"), &values(&[("app_name", "a")])).is_err());
    }

    #[test]
    fn responses_are_read() {
        let plain = b"HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\n[1]\nextra";
        assert_eq!(parse_response(plain).unwrap(), b"[1]\n");
        let chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\n[1,\r\n2\r\n2]\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap(), b"[1,2]");
        let refused = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_response(refused).unwrap_err().contains("refused"));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err());
    }

    #[test]
    fn ice_servers_of_every_shape_are_read() {
        // Cloudflare's documented answer.
        let cloudflare = br#"{"iceServers":[{"urls":["stun:stun.cloudflare.com:3478"]},
            {"urls":["turn:turn.cloudflare.com:3478?transport=udp","turn:turn.cloudflare.com:53?transport=udp",
            "turns:turn.cloudflare.com:5349?transport=tcp"],"username":"u1","credential":"p1"}]}"#;
        let s = ice_servers(cloudflare).unwrap();
        assert_eq!(
            (s.address.as_str(), s.username.as_str(), s.password.as_str()),
            ("turn:turn.cloudflare.com:3478?transport=udp", "u1", "p1")
        );
        // Metered's: a bare list, plain `turn:` meaning UDP.
        let metered = br#"[{"urls":"stun:stun.relay.metered.ca:80"},
            {"urls":"turn:standard.relay.metered.ca:80?transport=tcp","username":"u","credential":"p"},
            {"urls":"turn:standard.relay.metered.ca:80","username":"u","credential":"p"}]"#;
        assert_eq!(
            ice_servers(metered).unwrap().host_port(),
            "standard.relay.metered.ca:80"
        );
        // One object.
        let one =
            br#"{"iceServers":{"urls":"turn:a.example:3478","username":"u","credential":"p"}}"#;
        assert_eq!(ice_servers(one).unwrap().host_port(), "a.example:3478");
        assert!(
            ice_servers(br#"[{"urls":"turns:a:443","username":"u","credential":"p"}]"#).is_err()
        );
        assert!(ice_servers(b"nonsense").is_err());
    }
}
