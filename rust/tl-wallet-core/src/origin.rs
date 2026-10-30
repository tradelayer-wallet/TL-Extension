//! Web origin parsing: `scheme://host[:port]`, canonicalized the way `new URL(x).origin`
//! does for the cases the wallet accepts (http/https, ASCII host, default port stripped).

use crate::error::ProviderError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin(String);

impl Origin {
    /// Parse the origin of a URL or origin string. Userinfo, non-http(s) schemes, non-ASCII
    /// or malformed hosts and out-of-range ports are rejected (the legacy code mapped
    /// failures to `null`, which then failed the allow-list; here they are typed errors).
    pub fn from_url(url: &str) -> Result<Origin, ProviderError> {
        const BAD: ProviderError = ProviderError::InvalidRequest("malformed origin");
        if url.len() > 2048 || !url.is_ascii() {
            return Err(BAD);
        }
        let (scheme, rest) = url.split_once("://").ok_or(BAD)?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "https" => 443u16,
            "http" => 80u16,
            _ => return Err(BAD),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        if authority.is_empty() || authority.contains('@') || authority.contains('[') {
            return Err(BAD);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.len() > 5 {
                    return Err(BAD);
                }
                let port: u16 = p.parse().map_err(|_| BAD)?;
                (h, Some(port))
            }
            None => (authority, None),
        };
        let host = host.to_ascii_lowercase();
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && !host.starts_with('.')
            && !host.ends_with('.')
            && !host.contains("..")
            && host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        if !valid_host {
            return Err(BAD);
        }
        let mut out = format!("{scheme}://{host}");
        if let Some(p) = port {
            if p != default_port {
                out.push_str(&format!(":{p}"));
            }
        }
        Ok(Origin(out))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_https(&self) -> bool {
        self.0.starts_with("https://")
    }

    /// Host without port.
    pub fn host(&self) -> &str {
        let rest = self.0.split_once("://").map(|x| x.1).unwrap_or("");
        rest.split(':').next().unwrap_or("")
    }
}
