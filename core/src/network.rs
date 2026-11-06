use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub query_count: u64,
}

pub struct NetworkTracker {
    // Shard counter updates by client IP to avoid a global write lock per query.
    devices: DashMap<IpAddr, DeviceInfo>,
    admission: std::sync::Mutex<()>,
    neighbors: arc_swap::ArcSwap<std::collections::HashMap<IpAddr, String>>,
    max_entries: usize,
    entry_ttl: Duration,
}

impl Default for NetworkTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTracker {
    pub fn new() -> Self {
        Self::with_limits(100_000, Duration::from_secs(24 * 60 * 60))
    }

    pub fn with_limits(max_entries: usize, entry_ttl: Duration) -> Self {
        Self {
            devices: DashMap::new(),
            admission: std::sync::Mutex::new(()),
            neighbors: arc_swap::ArcSwap::from_pointee(std::collections::HashMap::new()),
            max_entries,
            entry_ttl,
        }
    }

    pub async fn track_query(&self, ip: IpAddr) {
        let now = SystemTime::now();
        if let Some(mut entry) = self.devices.get_mut(&ip) {
            self.update_device(&mut entry, now);
            return;
        }

        if self.max_entries == 0 {
            return;
        }
        // Only new-device admission is serialized. Recheck after taking the
        // lock: another request may have inserted this IP in the meantime.
        let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut entry) = self.devices.get_mut(&ip) {
            self.update_device(&mut entry, now);
            return;
        }
        if self.devices.len() >= self.max_entries {
            // Materialize the key before removing it. Keeping the iterator
            // temporary alive during `remove` would retain a shard guard and
            // deadlock when the map is at capacity.
            let oldest_ip = self.devices.iter().next().map(|entry| *entry.key());
            if let Some(oldest_ip) = oldest_ip {
                self.devices.remove(&oldest_ip);
            }
        }
        self.devices.insert(
            ip,
            DeviceInfo {
                ip,
                mac: self.neighbors.load().get(&ip).cloned(),
                first_seen: now,
                last_seen: now,
                query_count: 1,
            },
        );
    }

    fn update_device(&self, device: &mut DeviceInfo, now: SystemTime) {
        if is_expired(device.last_seen, now, self.entry_ttl) {
            device.first_seen = now;
            device.query_count = 0;
        }
        device.last_seen = now;
        let neighbors = self.neighbors.load();
        let mac = neighbors.get(&device.ip);
        if device.mac.as_ref() != mac {
            device.mac = mac.cloned();
        }
        device.query_count += 1;
    }

    async fn update_mac_addresses(&self) {
        let neighbors = match tokio::task::spawn_blocking(crate::neighbors::read).await {
            Ok(Ok(neighbors)) => neighbors,
            error => {
                tracing::debug!("Neighbor discovery unavailable: {error:?}");
                std::collections::HashMap::new()
            }
        };
        self.replace_neighbors(neighbors);
    }

    fn replace_neighbors(&self, neighbors: std::collections::HashMap<IpAddr, String>) {
        // Absence or failure invalidates old identity; never retain a stale
        // whitelist after lease turnover or a failed neighbor lookup.
        for mut device in self.devices.iter_mut() {
            device.mac = neighbors.get(device.key()).cloned();
        }
        self.neighbors.store(Arc::new(neighbors));
    }

    /// Refreshes neighbor mappings off the query path; device lookups use only memory.
    pub fn start_arp_refresh_task(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                self.update_mac_addresses().await;
            }
        });
    }

    pub async fn get_devices(&self) -> Vec<DeviceInfo> {
        let now = SystemTime::now();
        let expired: Vec<IpAddr> = self
            .devices
            .iter()
            .filter(|entry| is_expired(entry.last_seen, now, self.entry_ttl))
            .map(|entry| *entry.key())
            .collect();
        for ip in expired {
            self.devices.remove_if(&ip, |_, device| {
                is_expired(device.last_seen, SystemTime::now(), self.entry_ttl)
            });
        }
        self.devices.iter().map(|e| e.value().clone()).collect()
    }

    /// Looks up one client without cloning or scanning the whole device table.
    pub fn find_device(&self, ip: &IpAddr) -> Option<DeviceInfo> {
        let entry = self.devices.get(ip)?;
        if is_expired(entry.last_seen, SystemTime::now(), self.entry_ttl) {
            drop(entry);
            self.devices.remove_if(ip, |_, device| {
                is_expired(device.last_seen, SystemTime::now(), self.entry_ttl)
            });
            None
        } else {
            Some(entry.value().clone())
        }
    }
}

fn is_expired(last_seen: SystemTime, now: SystemTime, ttl: Duration) -> bool {
    now.duration_since(last_seen).is_ok_and(|age| age >= ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_admission_preserves_counts_and_capacity() {
        let tracker = Arc::new(NetworkTracker::with_limits(8, Duration::from_secs(60)));
        let barrier = Arc::new(tokio::sync::Barrier::new(64));
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let tracker = tracker.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                tracker.track_query("10.0.0.1".parse().unwrap()).await;
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            tracker
                .find_device(&"10.0.0.1".parse().unwrap())
                .unwrap()
                .query_count,
            64
        );
        let mut tasks = Vec::new();
        for n in 2..100 {
            let tracker = tracker.clone();
            tasks.push(tokio::spawn(async move {
                tracker
                    .track_query(format!("10.0.0.{n}").parse().unwrap())
                    .await;
                assert!(tracker.devices.len() <= 8);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(tracker.devices.len(), 8);
    }

    #[tokio::test]
    async fn test_neighbor_snapshot_covers_new_devices_and_clears_stale_identity() {
        let tracker = NetworkTracker::new();
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        tracker.replace_neighbors(std::collections::HashMap::from([(
            ip,
            "aa:bb:cc:dd:ee:01".into(),
        )]));
        tracker.track_query(ip).await;
        assert_eq!(
            tracker.find_device(&ip).unwrap().mac.as_deref(),
            Some("aa:bb:cc:dd:ee:01")
        );
        tracker.replace_neighbors(std::collections::HashMap::from([(
            ip,
            "aa:bb:cc:dd:ee:02".into(),
        )]));
        assert_eq!(
            tracker.find_device(&ip).unwrap().mac.as_deref(),
            Some("aa:bb:cc:dd:ee:02")
        );
        tracker.replace_neighbors(std::collections::HashMap::new());
        assert!(tracker.find_device(&ip).unwrap().mac.is_none());
    }

    #[tokio::test]
    async fn test_find_device_avoids_full_table_scan_semantics() {
        let tracker = NetworkTracker::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        tracker.track_query(ip1).await;
        tracker.track_query(ip2).await;
        tracker.track_query(ip1).await;

        let dev1 = tracker.find_device(&ip1).expect("ip1 should be tracked");
        assert_eq!(dev1.query_count, 2);

        let dev2 = tracker.find_device(&ip2).expect("ip2 should be tracked");
        assert_eq!(dev2.query_count, 1);

        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        assert!(tracker.find_device(&ip3).is_none());
    }

    #[tokio::test]
    async fn test_get_devices_returns_all_tracked_devices() {
        let tracker = NetworkTracker::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        tracker.track_query(ip1).await;
        tracker.track_query(ip2).await;

        let devices = tracker.get_devices().await;
        assert_eq!(devices.len(), 2);
    }

    #[tokio::test]
    async fn test_tracker_is_bounded_and_entries_age_out() {
        let tracker = NetworkTracker::with_limits(2, Duration::from_millis(1));
        for octet in 1..=3 {
            tracker
                .track_query(format!("10.0.0.{octet}").parse().unwrap())
                .await;
        }
        assert!(tracker.get_devices().await.len() <= 2);

        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(tracker.get_devices().await.is_empty());
    }
}
