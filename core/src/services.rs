#[derive(Debug, Clone)]
pub struct BlockedService {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub wildcards: &'static [&'static str],
}

pub static BLOCKED_SERVICES: &[BlockedService] = &[
    BlockedService {
        id: "tiktok",
        name: "TikTok",
        description: "TikTok short-form video application",
        wildcards: &[
            "tiktok.com",
            "tiktokv.com",
            "tiktokcdn.com",
            "byteoversea.com",
            "ibytedtos.com",
            "muscdn.com",
            "musical.ly",
        ],
    },
    BlockedService {
        id: "youtube",
        name: "YouTube",
        description: "YouTube video platform and services",
        wildcards: &[
            "youtube.com",
            "youtubei.googleapis.com",
            "ytimg.com",
            "ytimg.l.google.com",
            "youtube.l.google.com",
            "ytstatic.l.google.com",
            "googlevideo.com",
            "youtu.be",
        ],
    },
    BlockedService {
        id: "facebook",
        name: "Facebook & Instagram",
        description: "Facebook, Instagram, and Messenger portals",
        wildcards: &[
            "facebook.com",
            "facebook.net",
            "fbcdn.net",
            "fbsbx.com",
            "instagram.com",
            "cdninstagram.com",
            "m.me",
        ],
    },
    BlockedService {
        id: "steam",
        name: "Steam",
        description: "Steam gaming store, community, and downloads",
        wildcards: &[
            "steampowered.com",
            "steamcommunity.com",
            "steamgames.com",
            "steamusercontent.com",
            "steamcontent.com",
            "steamstatic.com",
            "valvecorp.com",
        ],
    },
    BlockedService {
        id: "fortnite",
        name: "Fortnite",
        description: "Fortnite game and Epic Games services",
        wildcards: &["fortnite.com", "epicgames.com", "unrealengine.com"],
    },
    BlockedService {
        id: "roblox",
        name: "Roblox",
        description: "Roblox gaming and creation platform",
        wildcards: &["roblox.com", "rbxcdn.com"],
    },
];

/// Indexed lookup: service ids are resolved on every DNS query.
static SERVICES_BY_ID: std::sync::LazyLock<
    std::collections::HashMap<&'static str, &'static BlockedService>,
> = std::sync::LazyLock::new(|| BLOCKED_SERVICES.iter().map(|s| (s.id, s)).collect());

pub fn service_by_id(id: &str) -> Option<&'static BlockedService> {
    SERVICES_BY_ID.get(id).copied()
}

/// Matches an exact domain or subdomain without allocations. Domain names
/// arrive as ASCII/punycode, so ASCII case comparison is sufficient.
pub fn is_domain_in_wildcard(domain: &str, wildcard: &str) -> bool {
    let d = domain.trim_end_matches('.');
    let w = wildcard.trim_end_matches('.');

    if d.eq_ignore_ascii_case(w) {
        return true;
    }

    // Match only at a label boundary: "notexample.com" is not under "example.com".
    d.len() > w.len()
        && d.as_bytes()[d.len() - w.len() - 1] == b'.'
        && d[d.len() - w.len()..].eq_ignore_ascii_case(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_and_subdomain_match() {
        assert!(is_domain_in_wildcard("tiktok.com", "tiktok.com"));
        assert!(is_domain_in_wildcard("www.tiktok.com", "tiktok.com"));
        assert!(is_domain_in_wildcard("a.b.tiktok.com", "tiktok.com"));
    }

    #[test]
    fn test_trailing_dot_is_ignored_on_both_sides() {
        assert!(is_domain_in_wildcard("www.tiktok.com.", "tiktok.com"));
        assert!(is_domain_in_wildcard("tiktok.com.", "tiktok.com."));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(is_domain_in_wildcard("WWW.TikTok.COM", "tiktok.com"));
        assert!(is_domain_in_wildcard("www.tiktok.com", "TikTok.Com"));
    }

    #[test]
    fn test_label_boundary_is_respected() {
        // A textual suffix alone must not match across a label boundary.
        assert!(!is_domain_in_wildcard("nottiktok.com", "tiktok.com"));
        assert!(!is_domain_in_wildcard("eviltiktok.com", "tiktok.com"));
    }

    #[test]
    fn test_non_matches() {
        assert!(!is_domain_in_wildcard("example.com", "tiktok.com"));
        // Shorter than the wildcard: must not panic on the index arithmetic.
        assert!(!is_domain_in_wildcard("com", "tiktok.com"));
        assert!(!is_domain_in_wildcard("", "tiktok.com"));
    }

    #[test]
    fn test_service_by_id_matches_linear_scan() {
        for svc in BLOCKED_SERVICES {
            assert_eq!(service_by_id(svc.id).map(|s| s.id), Some(svc.id));
        }
        assert!(service_by_id("not-a-service").is_none());
    }
}
