//! Peer identity extraction — bare address parsing and network classification.

use std::fmt;

/// Network type as reported by Bitcoin Core's `getpeerinfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Ipv4,
    Ipv6,
    Onion,
    I2p,
    Cjdns,
}

impl Network {
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Ipv4 => "ipv4",
            Network::Ipv6 => "ipv6",
            Network::Onion => "onion",
            Network::I2p => "i2p",
            Network::Cjdns => "cjdns",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Combined peer identity for DB lookups.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    pub address: String,
    pub network: Network,
}

/// Classify network from Bitcoin Core's `getpeerinfo` "network" field.
pub fn classify_network(network: &str) -> Network {
    match network {
        "ipv4" => Network::Ipv4,
        "ipv6" => Network::Ipv6,
        "onion" => Network::Onion,
        "i2p" => Network::I2p,
        "cjdns" => Network::Cjdns,
        // Default unknown networks to ipv4 — should not happen with Bitcoin Core
        _ => Network::Ipv4,
    }
}

/// Strip port from `getpeerinfo` addr field, returning the bare IP or overlay address.
///
/// - IPv4: `1.2.3.4:8333` → `1.2.3.4`
/// - IPv6: `[::1]:8333` → `::1`
/// - Tor: `abc...xyz.onion:8333` → `abc...xyz.onion`
/// - I2P: `abc...xyz.b32.i2p:0` → `abc...xyz.b32.i2p`
pub fn bare_address(addr: &str) -> &str {
    // IPv6 bracket notation: [addr]:port
    if addr.starts_with('[') {
        if let Some(bracket_end) = addr.find(']') {
            return &addr[1..bracket_end];
        }
        // Malformed bracket notation — return as-is minus the leading bracket
        return addr.trim_start_matches('[');
    }

    // For everything else (IPv4, .onion, .i2p), split on last colon.
    // This handles `addr:port` format.
    match addr.rfind(':') {
        Some(pos) => &addr[..pos],
        None => addr,
    }
}

/// Extract a `PeerIdentity` from a `getpeerinfo` entry's addr and network fields.
pub fn peer_identity(addr: &str, network: &str) -> PeerIdentity {
    PeerIdentity {
        address: bare_address(addr).to_string(),
        network: classify_network(network),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── bare_address ──────────────────────────────────────────────────

    #[test]
    fn ipv4_strips_port() {
        assert_eq!(bare_address("1.2.3.4:8333"), "1.2.3.4");
    }

    #[test]
    fn ipv6_strips_brackets_and_port() {
        assert_eq!(bare_address("[2001:db8::1]:8333"), "2001:db8::1");
    }

    #[test]
    fn ipv6_localhost() {
        assert_eq!(bare_address("[::1]:8333"), "::1");
    }

    #[test]
    fn onion_strips_port() {
        assert_eq!(
            bare_address("abcdef1234567890.onion:8333"),
            "abcdef1234567890.onion"
        );
    }

    #[test]
    fn i2p_strips_port() {
        assert_eq!(bare_address("abcdef.b32.i2p:0"), "abcdef.b32.i2p");
    }

    #[test]
    fn no_port_returns_as_is() {
        assert_eq!(bare_address("1.2.3.4"), "1.2.3.4");
    }

    // ── classify_network ──────────────────────────────────────────────

    #[test]
    fn classifies_all_known_networks() {
        assert_eq!(classify_network("ipv4"), Network::Ipv4);
        assert_eq!(classify_network("ipv6"), Network::Ipv6);
        assert_eq!(classify_network("onion"), Network::Onion);
        assert_eq!(classify_network("i2p"), Network::I2p);
        assert_eq!(classify_network("cjdns"), Network::Cjdns);
    }

    #[test]
    fn unknown_network_defaults_to_ipv4() {
        assert_eq!(classify_network("garlic"), Network::Ipv4);
    }

    // ── peer_identity ─────────────────────────────────────────────────

    #[test]
    fn peer_identity_ipv4() {
        let id = peer_identity("1.2.3.4:8333", "ipv4");
        assert_eq!(id.address, "1.2.3.4");
        assert_eq!(id.network, Network::Ipv4);
    }

    #[test]
    fn peer_identity_ipv6() {
        let id = peer_identity("[2001:db8::1]:8333", "ipv6");
        assert_eq!(id.address, "2001:db8::1");
        assert_eq!(id.network, Network::Ipv6);
    }

    #[test]
    fn peer_identity_onion() {
        let id = peer_identity("abc123.onion:8333", "onion");
        assert_eq!(id.address, "abc123.onion");
        assert_eq!(id.network, Network::Onion);
    }

    // ── Display ───────────────────────────────────────────────────────

    #[test]
    fn network_display() {
        assert_eq!(format!("{}", Network::Ipv4), "ipv4");
        assert_eq!(format!("{}", Network::Onion), "onion");
    }
}
