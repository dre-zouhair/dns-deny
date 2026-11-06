pub mod l1;
pub mod l2;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheKey {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: DNSClass,
}

pub type ResponseSections = (Vec<Record>, Vec<Record>, Vec<Record>);

#[derive(Debug)]
struct AgedSections {
    elapsed: u64,
    records: std::sync::Arc<ResponseSections>,
}

#[derive(Debug)]
pub struct CachedResponse {
    pub response_code: ResponseCode,
    pub authenticated_data: bool,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    pub created_at: Instant,
    pub original_ttl: u32,
    payload_weight: std::sync::OnceLock<u32>,
    aged_sections: std::sync::Arc<arc_swap::ArcSwapOption<AgedSections>>,
}

impl Clone for CachedResponse {
    fn clone(&self) -> Self {
        Self {
            response_code: self.response_code,
            authenticated_data: self.authenticated_data,
            answers: self.answers.clone(),
            authorities: self.authorities.clone(),
            additionals: self.additionals.clone(),
            created_at: self.created_at,
            original_ttl: self.original_ttl,
            // Reset derived views and accounting for this independent payload.
            payload_weight: Default::default(),
            aged_sections: Default::default(),
        }
    }
}

impl CachedResponse {
    pub fn answers(&self) -> &[Record] {
        &self.answers
    }
    pub fn authorities(&self) -> &[Record] {
        &self.authorities
    }
    pub fn additionals(&self) -> &[Record] {
        &self.additionals
    }

    pub fn new(
        response_code: ResponseCode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        additionals: Vec<Record>,
        negative_ttl_fallback: u32,
    ) -> Self {
        let original_ttl = if response_code == ResponseCode::NXDomain || answers.is_empty() {
            // Negative caching follows RFC 2308: use the lesser of the SOA RR
            // TTL and its MINIMUM field, falling back only when no SOA exists.
            authoritative_negative_ttl(&authorities).unwrap_or(negative_ttl_fallback)
        } else {
            // Authority/additional records must not shorten a live answer.
            answers.iter().map(|record| record.ttl).min().unwrap_or(0)
        };

        Self {
            response_code,
            authenticated_data: false,
            answers,
            authorities,
            additionals,
            created_at: Instant::now(),
            original_ttl,
            payload_weight: Default::default(),
            aged_sections: Default::default(),
        }
    }

    pub fn new_with_negative_ttl(
        response_code: ResponseCode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        additionals: Vec<Record>,
        negative_ttl: Option<u32>,
        negative_ttl_fallback: u32,
        authenticated_data: bool,
    ) -> Self {
        let is_negative = response_code == ResponseCode::NXDomain || answers.is_empty();
        let original_ttl = if is_negative {
            negative_ttl
                .or_else(|| authoritative_negative_ttl(&authorities))
                .unwrap_or(negative_ttl_fallback)
        } else {
            answers.iter().map(|record| record.ttl).min().unwrap_or(0)
        };

        Self {
            response_code,
            authenticated_data,
            answers,
            authorities,
            additionals,
            created_at: Instant::now(),
            original_ttl,
            payload_weight: Default::default(),
            aged_sections: Default::default(),
        }
    }

    /// Computes the remaining TTL. Returns `None` if the cache entry has expired.
    pub fn remaining_ttl(&self, now: Instant) -> Option<u32> {
        let elapsed = now
            .checked_duration_since(self.created_at)
            .unwrap_or_default()
            .as_secs();
        if elapsed >= u64::from(self.original_ttl) {
            None
        } else {
            Some(self.original_ttl - elapsed as u32)
        }
    }

    /// Return sections with each record's own TTL reduced by elapsed time.
    /// Answers are one RRset/chain and expire together; authority/additional
    /// records are removed independently when their TTL reaches zero.
    pub fn sections_at(&self, now: Instant) -> Option<std::sync::Arc<ResponseSections>> {
        let elapsed = now
            .checked_duration_since(self.created_at)
            .unwrap_or_default()
            .as_secs();
        if elapsed >= u64::from(self.original_ttl) {
            return None;
        }

        if let Some(cached) = self.aged_sections.load_full()
            && cached.elapsed == elapsed
        {
            return Some(cached.records.clone());
        }
        let mut answers = self.answers.clone();
        if answers
            .iter()
            .any(|record| u64::from(record.ttl) <= elapsed)
        {
            return None;
        }
        for record in &mut answers {
            record.ttl = record.ttl.saturating_sub(elapsed as u32);
        }

        let adjust = |records: &[Record]| {
            records
                .iter()
                .filter_map(|record| {
                    let remaining = u64::from(record.ttl).checked_sub(elapsed)?;
                    if remaining == 0 {
                        return None;
                    }
                    let mut record = record.clone();
                    record.ttl = remaining as u32;
                    Some(record)
                })
                .collect()
        };
        let records = std::sync::Arc::new((
            answers,
            adjust(&self.authorities),
            adjust(&self.additionals),
        ));
        self.aged_sections
            .store(Some(std::sync::Arc::new(AgedSections {
                elapsed,
                records: records.clone(),
            })));
        Some(records)
    }

    pub fn is_cacheable(response_code: ResponseCode) -> bool {
        matches!(
            response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        )
    }
}

pub(crate) fn authoritative_negative_ttl(authorities: &[Record]) -> Option<u32> {
    authorities.iter().find_map(|record| {
        if record.record_type() != RecordType::SOA {
            return None;
        }
        let RData::SOA(soa) = &record.data else {
            return None;
        };
        Some(record.ttl.min(soa.minimum))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::l1::L1Cache;
    use crate::cache::l2::L2Cache;
    use std::time::Duration;

    #[tokio::test]
    async fn cache_layers_share_records_without_cloning_payloads() {
        let response = std::sync::Arc::new(CachedResponse::new(
            ResponseCode::NoError,
            vec![Record::from_rdata(
                Name::root(),
                300,
                RData::A(std::net::Ipv4Addr::LOCALHOST.into()),
            )],
            vec![],
            vec![],
            60,
        ));
        let key = CacheKey {
            name: Name::root(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
        };
        let l1 = L1Cache::new(10);
        let l2 = L2Cache::new(1024 * 1024);
        l1.insert(key.clone(), response.clone());
        l2.insert(key.clone(), response.clone()).await;
        assert!(std::sync::Arc::ptr_eq(&response, &l1.get(&key).unwrap()));
        assert!(std::sync::Arc::ptr_eq(
            &response,
            &l2.get(&key).await.unwrap()
        ));
        let aged = response
            .sections_at(response.created_at + Duration::from_secs(10))
            .unwrap();
        assert_eq!(aged.0[0].ttl, 290);
        assert_eq!(response.answers[0].ttl, 300);
    }

    #[test]
    fn cached_ttl_views_are_reused_without_mutating_in_flight_answers() {
        let name = Name::from_ascii("ttl.example.").unwrap();
        let response = CachedResponse::new(
            ResponseCode::NoError,
            vec![Record::from_rdata(
                name,
                60,
                RData::A(std::net::Ipv4Addr::LOCALHOST.into()),
            )],
            vec![],
            vec![],
            60,
        );
        let first = response
            .sections_at(response.created_at + Duration::from_secs(10))
            .unwrap();
        let same = response
            .sections_at(response.created_at + Duration::from_millis(10999))
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&first, &same));
        let next = response
            .sections_at(response.created_at + Duration::from_secs(11))
            .unwrap();
        assert_eq!(first.0[0].ttl, 50);
        assert_eq!(next.0[0].ttl, 49);
        assert_eq!(response.answers[0].ttl, 60);
        assert!(
            response
                .sections_at(response.created_at + Duration::from_secs(60))
                .is_none()
        );
        let mut copy = response.clone();
        copy.answers[0].ttl = 40;
        assert_eq!(
            copy.sections_at(copy.created_at + Duration::from_secs(11))
                .unwrap()
                .0[0]
                .ttl,
            29
        );
    }

    #[test]
    fn test_cached_response_ttl() {
        let answers = vec![Record::from_rdata(
            Name::root(),
            300,
            hickory_proto::rr::RData::A(std::net::Ipv4Addr::new(1, 1, 1, 1).into()),
        )];
        let resp = CachedResponse::new(ResponseCode::NoError, answers, vec![], vec![], 60);
        assert_eq!(resp.original_ttl, 300);

        let now = Instant::now();
        assert_eq!(resp.remaining_ttl(now), Some(300));

        let future = now + Duration::from_secs(100);
        assert_eq!(resp.remaining_ttl(future), Some(200));

        let expired = now + Duration::from_secs(350);
        assert_eq!(resp.remaining_ttl(expired), None);
    }

    #[test]
    fn test_negative_caching_ttl() {
        let authorities = vec![Record::from_rdata(
            Name::root(),
            300,
            hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::root(),
                Name::root(),
                1,
                2,
                3,
                4,
                60,
            )),
        )];
        let resp = CachedResponse::new(ResponseCode::NXDomain, vec![], authorities, vec![], 120);
        // RFC 2308 uses min(SOA RR TTL, SOA MINIMUM), not a configurable floor.
        assert_eq!(resp.original_ttl, 60);

        let authorities = vec![Record::from_rdata(
            Name::root(),
            30,
            hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::root(),
                Name::root(),
                1,
                2,
                3,
                4,
                60,
            )),
        )];
        let resp = CachedResponse::new(ResponseCode::NXDomain, vec![], authorities, vec![], 60);
        assert_eq!(resp.original_ttl, 30);

        // No SOA record uses the configured fallback.
        let resp = CachedResponse::new(ResponseCode::NXDomain, vec![], vec![], vec![], 60);
        assert_eq!(resp.original_ttl, 60);
    }

    #[test]
    fn test_per_record_ttl_and_independent_additional_expiry() {
        let name = Name::from_ascii("alias.example.").unwrap();
        let cname = Record::from_rdata(
            name.clone(),
            60,
            hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(
                Name::from_ascii("target.example.").unwrap(),
            )),
        );
        let address = Record::from_rdata(
            Name::from_ascii("target.example.").unwrap(),
            300,
            hickory_proto::rr::RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1).into()),
        );
        let authority = Record::from_rdata(
            Name::root(),
            10,
            hickory_proto::rr::RData::NS(hickory_proto::rr::rdata::NS(name.clone())),
        );
        let mut response = CachedResponse::new(
            ResponseCode::NoError,
            vec![cname, address],
            vec![authority],
            vec![],
            60,
        );
        response.created_at -= Duration::from_secs(20);

        let sections = response.sections_at(Instant::now()).unwrap();
        let (answers, authorities, _) = sections.as_ref();
        assert_eq!(answers[0].ttl, 40);
        assert_eq!(answers[1].ttl, 280);
        assert!(authorities.is_empty());
    }

    #[test]
    fn test_transient_codes_are_not_cacheable() {
        assert!(!CachedResponse::is_cacheable(ResponseCode::ServFail));
        assert!(!CachedResponse::is_cacheable(ResponseCode::Refused));
        assert!(CachedResponse::is_cacheable(ResponseCode::NoError));
        assert!(CachedResponse::is_cacheable(ResponseCode::NXDomain));
    }

    #[tokio::test]
    async fn test_l1_l2_caches() {
        let key = CacheKey {
            name: Name::root(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
        };

        let l1 = L1Cache::new(2);
        let l2 = L2Cache::new(1024 * 1024);

        let answers = vec![Record::from_rdata(
            Name::root(),
            300,
            hickory_proto::rr::RData::A(std::net::Ipv4Addr::new(1, 1, 1, 1).into()),
        )];
        let resp = CachedResponse::new(ResponseCode::NoError, answers, vec![], vec![], 60);

        assert!(l1.insert(key.clone(), resp.clone()));
        l2.insert(key.clone(), resp.clone()).await;

        assert!(l1.get(&key).is_some());
        assert!(l2.get(&key).await.is_some());

        let key2 = CacheKey {
            name: Name::root(),
            qtype: RecordType::AAAA,
            qclass: DNSClass::IN,
        };
        let key3 = CacheKey {
            name: Name::root(),
            qtype: RecordType::MX,
            qclass: DNSClass::IN,
        };
        assert!(l1.insert(key2.clone(), resp.clone()));
        assert!(l1.insert(key3.clone(), resp.clone()));
        assert!(l1.len() <= 2);
    }
}
