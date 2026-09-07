//! Header pass-through policy. The proxy forwards only the *semantic* Matrix
//! federation headers and drops everything else. An **allowlist** (not a
//! denylist) is used deliberately: the body is re-serialized JSON↔CBOR on every
//! hop, so any header a peer set describing the original body — a stale
//! `Content-Encoding`, a smuggled `Transfer-Encoding`/`Content-Length` — would
//! be a lie at the next hop. Listing what may pass, and dropping the rest,
//! means a header has to be explicitly understood to survive; framing headers
//! are recomputed per hop by the downstream HTTP client regardless.

/// Lowercase header names the proxy forwards verbatim. The only semantic header
/// this (signature-less, trusted-network) server uses is `authorization`: it
/// carries the `X-Matrix origin="…",destination="…"` credential the inbound
/// side reads to authenticate the origin (see `federation::auth`).
const ALLOWED: &[&str] = &["authorization"];

/// Lowercase prefixes the proxy forwards. Reserved for any future
/// low-bandwidth `X-Matrix-*` header; matches the `X-Matrix` auth scheme family.
const ALLOWED_PREFIXES: &[&str] = &["x-matrix"];

/// Internal sentinel that carries a binary (non-JSON) response's original
/// `Content-Type` across the wire, so the recipient's egress can restore it
/// verbatim instead of forcing `application/json`.
///
/// A federation media download answers `multipart/mixed; boundary=…` with a
/// BINARY body (a JSON metadata part, then raw content bytes). That body cannot
/// be JSON⇄CBOR transcoded, so the ingress passes it through untouched — but the
/// real `Content-Type` header is a per-hop framing header the allowlist drops,
/// and its `boundary` is exactly what the recipient's multipart parser needs.
/// The ingress stashes it here on the passthrough path; because the name rides
/// the `x-matrix` forwardable prefix, this one header survives both wires (HTTP
/// response headers and the CoAP `OPT_FWD_HEADER` option) with no transport
/// change. Its PRESENCE is also the egress discriminator: set → serve the body
/// verbatim under this type; absent → CBOR-decode to JSON as before. The egress
/// consumes and strips it so it never reaches the loopback homeserver.
pub const CONTENT_TYPE_SENTINEL: &str = "x-matrix-lb-content-type";

/// True if `name` (any case) may be forwarded verbatim to the next hop. Matrix
/// S2S *responses* carry no semantic headers, so on the response path this
/// forwards nothing.
pub fn is_forwardable(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ALLOWED.contains(&lower.as_str()) || ALLOWED_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// The `content-type` header value from a list, if present. Case-insensitive on
/// the name; the value is returned verbatim (it carries the `multipart/mixed`
/// `boundary` that must survive intact).
pub fn content_type(headers: &[(String, Vec<u8>)]) -> Option<&[u8]> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_slice())
}

/// True if `content_type`'s media type (the part before any `;` parameters) is
/// `application/json`. Only such a body is JSON⇄CBOR transcoded; anything else
/// (`multipart/mixed`, `application/octet-stream`, `image/*`, …) is opaque and
/// passes through untouched. An unparseable (non-UTF8) value is not JSON.
pub fn is_json_content_type(content_type: &[u8]) -> bool {
    std::str::from_utf8(content_type)
        .ok()
        .and_then(|s| s.split(';').next())
        .map(|essence| essence.trim().eq_ignore_ascii_case("application/json"))
        .unwrap_or(false)
}

/// Extract the unquoted `origin` auth-param from an `X-Matrix origin="…",…`
/// Authorization value. `None` if the scheme prefix or `origin` is absent.
///
/// Two callers, one parser: the transport-layer identity binding
/// (`Hub::origin_binding_violation`) and the pcap capture's peer naming, which
/// is the only peer identity the ingress has — an inbound `WireRequest` carries
/// no source. Mirrors `neutrino_http::federation::auth`'s parse, kept here so
/// the Matrix-agnostic transport needn't depend on the http crate; it extracts
/// the bytes only — the http layer still owns the real auth policy.
pub fn xmatrix_origin(value: &str) -> Option<&str> {
    let params = value.strip_prefix("X-Matrix ")?;
    for part in params.split(',') {
        let Some((key, val)) = part.split_once('=') else {
            continue;
        };
        if key.trim() == "origin" {
            return Some(val.trim().trim_matches('"'));
        }
    }
    None
}

/// The raw `authorization` header value, if the list carries one. Split out
/// because the transport binding must tell "no header" (defer to the upstream
/// auth gate) from "header present but unparseable" (hard reject), a
/// distinction [`claimed_origin`] collapses.
pub fn authorization(headers: &[(String, Vec<u8>)]) -> Option<&[u8]> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_slice())
}

/// The claimed `X-Matrix` origin `server_name` from a header list, if any.
pub fn claimed_origin(headers: &[(String, Vec<u8>)]) -> Option<&str> {
    std::str::from_utf8(authorization(headers)?)
        .ok()
        .and_then(xmatrix_origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_framing_and_hop_headers() {
        for h in ["Host", "content-length", "Content-Type", "Connection"] {
            assert!(!is_forwardable(h), "{h} must be stripped");
        }
    }

    #[test]
    fn forwards_authorization() {
        assert!(is_forwardable("Authorization"));
        assert!(is_forwardable("X-Matrix-Foo"));
    }

    // Allowlist: anything outside the Matrix auth headers is dropped — including
    // a peer-supplied header that would *lie* after the body is re-serialized
    // (e.g. a `Content-Encoding` describing the pre-transcode body, or a smuggled
    // framing header). A denylist would forward these by default.
    #[test]
    fn drops_unlisted_and_misleading_headers() {
        for h in [
            "Content-Encoding",
            "Transfer-Encoding",
            "X-Custom-Header",
            "User-Agent",
            "Cookie",
            "Forwarded",
        ] {
            assert!(!is_forwardable(h), "{h} must be dropped by the allowlist");
        }
    }
}
