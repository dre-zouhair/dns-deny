use crate::config::DeviceSchedule;
use chrono::{DateTime, Datelike, Local, Timelike};

use crate::config::{Config, PauseScope};
use crate::updater::BlocklistUpdater;
use filter::FilterVerdict;
use hickory_proto::rr::Name;

#[derive(Debug, PartialEq, Eq)]
pub enum DomainPolicy {
    Bypass,
    Service(String),
    Deny,
    Allow,
    Pass,
}

impl DomainPolicy {
    pub fn blocked(&self) -> bool {
        matches!(self, Self::Service(_) | Self::Deny)
    }
}

/// Shared ordering for DNS, aliases and the administration probe.
pub fn domain_policy(
    config: &Config,
    updater: &BlocklistUpdater,
    name: &Name,
    now: i64,
    bypass: bool,
) -> DomainPolicy {
    if bypass || config.is_paused(&PauseScope::Global, now) {
        return DomainPolicy::Bypass;
    }
    if !config.blocked_services.is_empty() || !config.custom_services.is_empty() {
        let domain = name.to_string();
        for id in &config.blocked_services {
            if !config.is_paused(&PauseScope::Service(id.clone()), now)
                && let Some(service) = crate::services::service_by_id(id)
                && service
                    .wildcards
                    .iter()
                    .any(|pattern| crate::services::is_domain_in_wildcard(&domain, pattern))
            {
                return DomainPolicy::Service(service.name.into());
            }
        }
        for service in &config.custom_services {
            if service.enabled
                && !config.is_paused(&PauseScope::Service(service.id.clone()), now)
                && service
                    .wildcards
                    .iter()
                    .any(|pattern| crate::services::is_domain_in_wildcard(&domain, pattern))
            {
                return DomainPolicy::Service(service.name.clone());
            }
        }
    }
    match updater.check_domain(name) {
        FilterVerdict::Allow => DomainPolicy::Allow,
        FilterVerdict::Block => DomainPolicy::Deny,
        FilterVerdict::Pass => DomainPolicy::Pass,
    }
}

/// Evaluates active device schedules against client IP or MAC address and returns the matching policy string (if any).
pub fn evaluate_schedule_policy(
    ip: &str,
    mac: Option<&str>,
    schedules: &[DeviceSchedule],
) -> Option<String> {
    evaluate_schedule_policy_at(Local::now(), ip, mac, schedules)
}

/// Injects the clock for deterministic overnight and day-boundary tests.
pub fn evaluate_schedule_policy_at(
    now: DateTime<Local>,
    ip: &str,
    mac: Option<&str>,
    schedules: &[DeviceSchedule],
) -> Option<String> {
    let index = ScheduleIndex::build(schedules).ok()?;
    let ip = crate::config::normalize_device_identifier(ip);
    let mac = mac.map(crate::config::normalize_device_identifier);
    index.evaluate(now, &ip, mac.as_deref()).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_mac_matches_regardless_of_case_and_separator() {
        let schedule = DeviceSchedule {
            ip: "AA-BB-CC-DD-EE-FF".to_string(),
            policy: "block".to_string(),
            days: vec!["sat".to_string()],
            start_time: "00:00".to_string(),
            end_time: "23:59".to_string(),
        };
        // 2024-01-06 is a Saturday.
        use chrono::TimeZone;
        let saturday_noon = Local.with_ymd_and_hms(2024, 1, 6, 12, 0, 0).unwrap();
        let result = evaluate_schedule_policy_at(
            saturday_noon,
            "192.168.1.60",
            Some("aa:bb:cc:dd:ee:ff"),
            &[schedule],
        );
        assert_eq!(result, Some("block".to_string()));
    }

    #[test]
    fn test_schedule_ip_matching() {
        let schedule = DeviceSchedule {
            ip: "192.168.1.50".to_string(),
            policy: "block".to_string(),
            days: vec![
                "mon".to_string(),
                "tue".to_string(),
                "wed".to_string(),
                "thu".to_string(),
                "fri".to_string(),
                "sat".to_string(),
                "sun".to_string(),
            ],
            start_time: "00:00".to_string(),
            end_time: "23:59".to_string(),
        };

        let result = evaluate_schedule_policy("192.168.1.50", None, &[schedule]);
        assert_eq!(result, Some("block".to_string()));
    }

    #[test]
    fn test_overnight_schedule_matches_after_midnight_on_following_day() {
        use chrono::TimeZone;
        let schedule = DeviceSchedule {
            ip: "192.168.1.50".to_string(),
            policy: "block".to_string(),
            days: vec!["fri".to_string()],
            start_time: "21:00".to_string(),
            end_time: "07:00".to_string(),
        };

        // 2024-01-06 is a Saturday; 02:00 falls within the Friday-21:00 to
        // Saturday-07:00 window even though only "fri" is listed in `days`.
        let saturday_2am = Local.with_ymd_and_hms(2024, 1, 6, 2, 0, 0).unwrap();
        let result = evaluate_schedule_policy_at(
            saturday_2am,
            "192.168.1.50",
            None,
            std::slice::from_ref(&schedule),
        );
        assert_eq!(result, Some("block".to_string()));

        // 2024-01-07 is a Sunday; 02:00 there is not covered by a
        // Friday-start window (that window already ended at 07:00 Saturday).
        let sunday_2am = Local.with_ymd_and_hms(2024, 1, 7, 2, 0, 0).unwrap();
        let result = evaluate_schedule_policy_at(sunday_2am, "192.168.1.50", None, &[schedule]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_schedule_non_matching_ip() {
        let schedule = DeviceSchedule {
            ip: "192.168.1.50".to_string(),
            policy: "block".to_string(),
            days: vec![
                "mon".to_string(),
                "tue".to_string(),
                "wed".to_string(),
                "thu".to_string(),
                "fri".to_string(),
                "sat".to_string(),
                "sun".to_string(),
            ],
            start_time: "00:00".to_string(),
            end_time: "23:59".to_string(),
        };

        let result = evaluate_schedule_policy("192.168.1.99", None, &[schedule]);
        assert_eq!(result, None);
    }
}

/// Parsed once per configuration publication, indexed by canonical identity.
#[derive(Debug, Default)]
pub(crate) struct ScheduleIndex {
    by_device: std::collections::HashMap<String, Vec<CompiledSchedule>>,
    mac_block_windows: Vec<(u8, u32, u32)>,
}
#[derive(Debug)]
struct CompiledSchedule {
    order: usize,
    days: u8,
    start: u32,
    end: u32,
    policy: String,
}

pub fn valid_device_identifier(value: &str) -> bool {
    if value.trim().parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let value = crate::config::normalize_device_identifier(value);
    let bytes = value.as_bytes();
    bytes.len() == 17
        && bytes.iter().enumerate().all(|(i, b)| {
            if i % 3 == 2 {
                *b == b':'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn minute(value: &str) -> Result<u32, String> {
    if value.len() != 5
        || value.as_bytes()[2] != b':'
        || !value
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(i, b)| i == 2 || b.is_ascii_digit())
    {
        return Err("Schedule times must use HH:MM".into());
    }
    let hour: u32 = value[..2].parse().map_err(|_| "Invalid schedule hour")?;
    let minute: u32 = value[3..].parse().map_err(|_| "Invalid schedule minute")?;
    if hour >= 24 || minute >= 60 {
        return Err("Schedule time is outside 00:00–23:59".into());
    }
    Ok(hour * 60 + minute)
}
impl ScheduleIndex {
    pub(crate) fn build(schedules: &[DeviceSchedule]) -> Result<Self, String> {
        let mut index = Self::default();
        let names = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
        for (order, schedule) in schedules.iter().enumerate() {
            if !valid_device_identifier(&schedule.ip) {
                return Err("Schedule requires a valid IP or MAC".into());
            }
            if !matches!(schedule.policy.as_str(), "block" | "whitelist") {
                return Err("Unknown schedule policy".into());
            }
            let start = minute(&schedule.start_time)?;
            let end = minute(&schedule.end_time)?;
            if start == end {
                return Err("Schedule start and end must differ".into());
            }
            if schedule.days.is_empty() {
                return Err("Schedule requires at least one day".into());
            }
            let mut days = 0u8;
            for day in &schedule.days {
                let Some(bit) = names.iter().position(|name| day.eq_ignore_ascii_case(name)) else {
                    return Err("Unknown schedule day".into());
                };
                days |= 1 << bit;
            }
            let id = crate::config::normalize_device_identifier(&schedule.ip);
            if id.parse::<std::net::IpAddr>().is_err() && schedule.policy == "block" {
                index.mac_block_windows.push((days, start, end));
            }
            index
                .by_device
                .entry(id)
                .or_default()
                .push(CompiledSchedule {
                    order,
                    days,
                    start,
                    end,
                    policy: schedule.policy.clone(),
                });
        }
        Ok(index)
    }
    pub(crate) fn blocks_unknown(&self, now: DateTime<Local>) -> bool {
        let today = now.weekday().num_days_from_monday();
        let yesterday = (today + 6) % 7;
        let current = now.hour() * 60 + now.minute();
        self.mac_block_windows.iter().any(|&(days, start, end)| {
            if start < end {
                days & (1 << today) != 0 && current >= start && current < end
            } else {
                (days & (1 << today) != 0 && current >= start)
                    || (days & (1 << yesterday) != 0 && current < end)
            }
        })
    }
    pub(crate) fn evaluate(
        &self,
        now: DateTime<Local>,
        ip: &str,
        mac: Option<&str>,
    ) -> Option<&str> {
        let today = now.weekday().num_days_from_monday();
        let yesterday = (today + 6) % 7;
        let current = now.hour() * 60 + now.minute();
        [Some(ip), mac]
            .into_iter()
            .flatten()
            .filter_map(|id| self.by_device.get(id))
            .flatten()
            .filter(|s| {
                if s.start < s.end {
                    s.days & (1 << today) != 0 && current >= s.start && current < s.end
                } else {
                    (s.days & (1 << today) != 0 && current >= s.start)
                        || (s.days & (1 << yesterday) != 0 && current < s.end)
                }
            })
            .min_by_key(|s| s.order)
            .map(|s| s.policy.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevicePolicy {
    Filtered,
    Block,
    Whitelist,
    IdentityUnknown,
}
