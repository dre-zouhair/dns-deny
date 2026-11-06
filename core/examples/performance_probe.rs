//! Reproducible local probes: cargo run -p core_dns --release --example performance_probe
//! Measures cache retrieval + TTL adjustment, refresh latency, and runtime
//! responsiveness during a large rule edit. Does not measure end-to-end QPS.
use core_dns::cache::{CacheKey, CachedResponse, l1::L1Cache};
use core_dns::updater::BlocklistUpdater;
use filter::{
    FilterEngine, exact::ExactFilter, regex_set::RegexFilter, snapshot::FilterSnapshot,
    trie::SubdomainTrie,
};
use hickory_proto::{
    op::ResponseCode,
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::TXT},
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}
struct CountingAllocator;
fn count_allocation() {
    let _ = TRACK.try_with(|active| {
        if active.get() {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
    });
}
// SAFETY: all memory operations are forwarded unchanged to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
fn engine() -> Arc<FilterEngine> {
    Arc::new(FilterEngine::new(FilterSnapshot::new(
        ExactFilter::new(),
        SubdomainTrie::new(),
        RegexFilter::new(&[], &[]).unwrap(),
    )))
}
fn cache_probe() {
    const ITERATIONS: u64 = 25_000;
    for count in [1, 8, 32] {
        let cache = L1Cache::new(100);
        let key = CacheKey {
            name: Name::from_ascii("probe.example.").unwrap(),
            qtype: RecordType::TXT,
            qclass: DNSClass::IN,
        };
        let answers = (0..count)
            .map(|_| {
                Record::from_rdata(
                    key.name.clone(),
                    3600,
                    RData::TXT(TXT::new(vec!["x".repeat(128)])),
                )
            })
            .collect();
        cache.insert(
            key.clone(),
            CachedResponse::new(ResponseCode::NoError, answers, vec![], vec![], 60),
        );
        let mut samples = Vec::new();
        let mut allocations = Vec::new();
        for _ in 0..7 {
            ALLOCATIONS.with(|count| count.set(0));
            TRACK.with(|active| active.set(true));
            let start = Instant::now();
            for _ in 0..ITERATIONS {
                let response = cache.get(black_box(&key)).unwrap();
                black_box(response.sections_at(Instant::now()).unwrap());
            }
            let elapsed = start.elapsed();
            TRACK.with(|active| active.set(false));
            samples.push(elapsed.as_nanos() as u64 / ITERATIONS);
            allocations.push(ALLOCATIONS.with(Cell::get) / ITERATIONS);
        }
        samples.sort_unstable();
        allocations.sort_unstable();
        println!(
            "cache_{count}_txt,{} ns/op,{} allocs/op",
            samples[3], allocations[3]
        );
    }
}
async fn refresh_probe() {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = server.accept().await {
            tokio::spawn(async move {
                let mut request = [0; 2048];
                let _ = socket.read(&mut request).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                let body = "blocked.example\n";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let updater = BlocklistUpdater::new_with_dir(
        engine(),
        (0..8).map(|i| format!("http://{address}/{i}")).collect(),
        dir.path().to_path_buf(),
    );
    let start = Instant::now();
    updater.refresh().await.unwrap();
    println!("refresh_8_sources_100ms,{} ms", start.elapsed().as_millis());
    task.abort();
}
async fn persistence_probe() {
    let dir = tempfile::tempdir().unwrap();
    let updater = BlocklistUpdater::new_with_dir(engine(), vec![], dir.path().to_path_buf());
    {
        let mut rules = updater.local_denies.lock().await;
        rules.extend((0..100_000).map(|i| format!("rule-{i}.example")));
    }
    let finished = Arc::new(AtomicBool::new(false));
    let flag = finished.clone();
    let monitor = tokio::spawn(async move {
        let mut worst = Duration::ZERO;
        while !flag.load(Ordering::Relaxed) {
            let start = Instant::now();
            tokio::time::sleep(Duration::from_millis(1)).await;
            worst = worst.max(start.elapsed().saturating_sub(Duration::from_millis(1)));
        }
        worst
    });
    tokio::task::yield_now().await;
    let start = Instant::now();
    updater
        .add_local_rule("new.example".into(), ingest::RuleAction::Deny)
        .await
        .unwrap();
    let elapsed = start.elapsed();
    finished.store(true, Ordering::Relaxed);
    println!(
        "edit_100k_rules,{} ms,max_timer_delay={} us",
        elapsed.as_millis(),
        monitor.await.unwrap().as_micros()
    );
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    cache_probe();
    refresh_probe().await;
    persistence_probe().await;
}
