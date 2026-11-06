use crate::config::LocalDnsRecord;
use hickory_proto::rr::{LowerName, Name};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Default)]
pub(crate) struct LocalDnsEntry {
    pub(crate) cname: Option<Name>,
    pub(crate) a: Vec<Ipv4Addr>,
    pub(crate) aaaa: Vec<Ipv6Addr>,
}

#[derive(Debug, Default)]
pub(crate) struct LocalDnsIndex {
    records: HashMap<LowerName, LocalDnsEntry>,
}

impl LocalDnsIndex {
    pub(crate) fn build(records: &[LocalDnsRecord]) -> Result<Self, String> {
        let mut index = Self::default();

        for (position, record) in records.iter().enumerate() {
            let owner = parse_name(&record.name, "owner", position)?;
            let owner_key = LowerName::from(owner);
            let entry = index.records.entry(owner_key).or_default();

            if record.record_type.eq_ignore_ascii_case("CNAME") {
                let target = parse_name(&record.value, "CNAME target", position)?;
                if !entry.a.is_empty() || !entry.aaaa.is_empty() {
                    return Err(format!(
                        "local DNS record {position}: CNAME cannot coexist with A or AAAA records for {}",
                        record.name
                    ));
                }
                if let Some(existing) = &entry.cname {
                    if existing != &target {
                        return Err(format!(
                            "local DNS record {position}: conflicting CNAME for {}",
                            record.name
                        ));
                    }
                } else {
                    entry.cname = Some(target);
                }
            } else if record.record_type.eq_ignore_ascii_case("A") {
                if entry.cname.is_some() {
                    return Err(format!(
                        "local DNS record {position}: A cannot coexist with CNAME records for {}",
                        record.name
                    ));
                }
                let address = record.value.trim().parse::<Ipv4Addr>().map_err(|error| {
                    format!(
                        "local DNS record {position}: invalid A value {:?}: {error}",
                        record.value
                    )
                })?;
                entry.a.push(address);
            } else if record.record_type.eq_ignore_ascii_case("AAAA") {
                if entry.cname.is_some() {
                    return Err(format!(
                        "local DNS record {position}: AAAA cannot coexist with CNAME records for {}",
                        record.name
                    ));
                }
                let address = record.value.trim().parse::<Ipv6Addr>().map_err(|error| {
                    format!(
                        "local DNS record {position}: invalid AAAA value {:?}: {error}",
                        record.value
                    )
                })?;
                entry.aaaa.push(address);
            } else {
                return Err(format!(
                    "local DNS record {position}: unsupported record type {:?}",
                    record.record_type
                ));
            }
        }

        Ok(index)
    }

    pub(crate) fn lookup(&self, query_name: &LowerName) -> Option<&LocalDnsEntry> {
        let mut normalized = query_name.clone();
        normalized.set_fqdn(true);
        self.records.get(&normalized)
    }
}

fn parse_name(value: &str, role: &str, position: usize) -> Result<Name, String> {
    let mut name = Name::from_str(value.trim()).map_err(|error| {
        format!(
            "local DNS record {position}: invalid {role} name {:?}: {error}",
            value
        )
    })?;
    // DNS queries are absolute. Treat config names without a trailing dot as
    // the same owner as their explicitly absolute spelling.
    name.set_fqdn(true);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, record_type: &str, value: &str) -> LocalDnsRecord {
        LocalDnsRecord {
            name: name.to_string(),
            record_type: record_type.to_string(),
            value: value.to_string(),
        }
    }

    fn query_name(value: &str) -> LowerName {
        LowerName::from(Name::from_str(value).unwrap())
    }

    #[test]
    fn owner_case_and_trailing_dot_share_index_entry() {
        let index = LocalDnsIndex::build(&[record("Example.COM", "A", "192.0.2.1")]).unwrap();
        let entry = index.lookup(&query_name("example.com.")).unwrap();
        assert_eq!(entry.a, [Ipv4Addr::new(192, 0, 2, 1)]);
    }

    #[test]
    fn parses_a_aaaa_and_cname_values() {
        let index = LocalDnsIndex::build(&[
            record("a.example", "A", "192.0.2.1"),
            record("aaaa.example.", "AAAA", "2001:db8::1"),
            record("alias.example", "CNAME", "Target.Example"),
        ])
        .unwrap();

        assert_eq!(index.lookup(&query_name("a.example.")).unwrap().a.len(), 1);
        assert_eq!(
            index.lookup(&query_name("aaaa.example")).unwrap().aaaa,
            [Ipv6Addr::from_str("2001:db8::1").unwrap()]
        );
        assert_eq!(
            index
                .lookup(&query_name("alias.example."))
                .unwrap()
                .cname
                .as_ref()
                .unwrap()
                .to_string(),
            "target.example."
        );
    }

    #[test]
    fn rejects_invalid_values_and_cname_coexistence() {
        assert!(LocalDnsIndex::build(&[record("bad", "A", "not-an-ip")]).is_err());
        assert!(LocalDnsIndex::build(&[record("bad", "CNAME", "not a name")]).is_err());
        assert!(
            LocalDnsIndex::build(&[
                record("same", "A", "192.0.2.1"),
                record("same.", "CNAME", "target.example"),
            ])
            .is_err()
        );
        assert!(
            LocalDnsIndex::build(&[
                record("same", "CNAME", "one.example"),
                record("same.", "CNAME", "two.example"),
            ])
            .is_err()
        );
    }

    #[test]
    fn lookup_remains_a_single_map_access_with_thousands_of_records() {
        let records = (0..10_000)
            .map(|index| record(&format!("host-{index}.example"), "A", "192.0.2.1"))
            .collect::<Vec<_>>();
        let index = LocalDnsIndex::build(&records).unwrap();

        assert!(index.lookup(&query_name("host-9999.example.")).is_some());
    }
}
