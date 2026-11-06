use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, broadcast};

type Key = (String, RecordType);

/// Deterministic responses used by resolver tests.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum Fixture {
    PositiveA {
        address: A,
        ttl: u32,
    },
    PositiveAaaa {
        address: AAAA,
        ttl: u32,
    },
    CnameThenA {
        canonical: Name,
        cname_ttl: u32,
        address: A,
        address_ttl: u32,
    },
    NxDomain {
        rr_ttl: u32,
        minimum: u32,
    },
    Nodata {
        rr_ttl: u32,
        minimum: u32,
    },
    Servfail,
    Referral,
    OversizedTxt,
    PositiveTxt {
        text: Vec<String>,
        ttl: u32,
    },
    SinkholeA,
    SinkholeAaaa,
    Mismatched,
    Delayed {
        delay: Duration,
        response: Box<Fixture>,
    },
}

impl Fixture {
    fn render(&self, request: &Message) -> Option<Message> {
        let query = request.queries.first()?.clone();
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.add_query(query.clone());

        match self {
            Self::PositiveA { address, ttl } => {
                response.add_answer(Record::from_rdata(query.name, *ttl, RData::A(*address)));
            }
            Self::PositiveAaaa { address, ttl } => {
                response.add_answer(Record::from_rdata(query.name, *ttl, RData::AAAA(*address)));
            }
            Self::CnameThenA {
                canonical,
                cname_ttl,
                address,
                address_ttl,
            } => {
                response.add_answer(Record::from_rdata(
                    query.name,
                    *cname_ttl,
                    RData::CNAME(CNAME(canonical.clone())),
                ));
                response.add_answer(Record::from_rdata(
                    canonical.clone(),
                    *address_ttl,
                    RData::A(*address),
                ));
            }
            Self::NxDomain { rr_ttl, minimum } | Self::Nodata { rr_ttl, minimum } => {
                response.metadata.response_code = if matches!(self, Self::NxDomain { .. }) {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::NoError
                };
                response.add_authority(Record::from_rdata(
                    Name::from_ascii("example.").expect("valid fixture name"),
                    *rr_ttl,
                    RData::SOA(SOA::new(
                        Name::from_ascii("ns.example.").expect("valid fixture name"),
                        Name::from_ascii("hostmaster.example.").expect("valid fixture name"),
                        1,
                        3600,
                        600,
                        86_400,
                        *minimum,
                    )),
                ));
            }
            Self::Servfail => response.metadata.response_code = ResponseCode::ServFail,
            Self::Referral => {
                let ns = Name::from_ascii("ns1.example.").expect("valid fixture name");
                response.add_authority(Record::from_rdata(
                    Name::from_ascii("example.").expect("valid fixture name"),
                    300,
                    RData::NS(NS(ns.clone())),
                ));
                response.add_additional(Record::from_rdata(
                    ns,
                    300,
                    RData::A(A::new(192, 0, 2, 53)),
                ));
            }
            Self::PositiveTxt { text, ttl } => {
                response.add_answer(Record::from_rdata(
                    query.name,
                    *ttl,
                    RData::TXT(TXT::new(text.clone())),
                ));
            }
            Self::OversizedTxt => {
                response.add_answer(Record::from_rdata(
                    query.name,
                    30,
                    RData::TXT(TXT::new((0..32).map(|_| "x".repeat(255)).collect())),
                ));
            }
            Self::SinkholeA => {
                response.add_answer(Record::from_rdata(
                    query.name,
                    30,
                    RData::A(A::new(0, 0, 0, 0)),
                ));
            }
            Self::SinkholeAaaa => {
                response.add_answer(Record::from_rdata(
                    query.name,
                    30,
                    RData::AAAA(AAAA(std::net::Ipv6Addr::UNSPECIFIED)),
                ));
            }
            Self::Mismatched => {
                response.metadata.id = request.metadata.id.wrapping_add(1);
                response.queries[0].name =
                    Name::from_ascii("mismatch.example.").expect("valid fixture name");
            }
            Self::Delayed {
                response: fixture, ..
            } => return fixture.render(request),
        }

        Some(response)
    }
}

/// A private UDP/TCP DNS server for deterministic resolver tests.
pub struct DnsMock {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    responses: Arc<RwLock<HashMap<Key, Fixture>>>,
    counts: Arc<RwLock<HashMap<Key, Arc<AtomicUsize>>>>,
    shutdown: broadcast::Sender<()>,
}

impl DnsMock {
    pub async fn start() -> std::io::Result<Self> {
        let udp = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let udp_addr = udp.local_addr()?;
        let tcp_addr = tcp.local_addr()?;
        let responses = Arc::new(RwLock::new(HashMap::new()));
        let counts = Arc::new(RwLock::new(HashMap::new()));
        let (shutdown, _) = broadcast::channel(2);

        tokio::spawn(serve_udp(
            udp,
            responses.clone(),
            counts.clone(),
            shutdown.subscribe(),
        ));
        tokio::spawn(serve_tcp(
            tcp,
            responses.clone(),
            counts.clone(),
            shutdown.subscribe(),
        ));

        Ok(Self {
            udp_addr,
            tcp_addr,
            responses,
            counts,
            shutdown,
        })
    }

    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    pub async fn set_fixture(&self, name: &str, qtype: RecordType, fixture: Fixture) {
        self.responses
            .write()
            .await
            .insert((canonical_name(name), qtype), fixture);
    }

    pub async fn request_count(&self, name: &str, qtype: RecordType) -> usize {
        self.counts
            .read()
            .await
            .get(&(canonical_name(name), qtype))
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }
}

impl Drop for DnsMock {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

fn canonical_name(name: &str) -> String {
    let name = name.trim_end_matches('.');
    format!("{name}.").to_ascii_lowercase()
}

async fn serve_udp(
    socket: UdpSocket,
    responses: Arc<RwLock<HashMap<Key, Fixture>>>,
    counts: Arc<RwLock<HashMap<Key, Arc<AtomicUsize>>>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let socket = Arc::new(socket);
    let mut tasks = tokio::task::JoinSet::new();
    let mut buffer = [0_u8; 65_535];
    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            result = socket.recv_from(&mut buffer) => {
                let Ok((length, peer)) = result else { break };
                let request = buffer[..length].to_vec();
                let socket = socket.clone();
                let responses = responses.clone();
                let counts = counts.clone();
                tasks.spawn(async move {
                    if let Some(response) = response_for(&request, &responses, &counts).await
                        && let Ok(bytes) = response.to_vec() {
                        let _ = socket.send_to(&bytes, peer).await;
                    }
                });
            }
        }
    }
}

async fn serve_tcp(
    listener: TcpListener,
    responses: Arc<RwLock<HashMap<Key, Fixture>>>,
    counts: Arc<RwLock<HashMap<Key, Arc<AtomicUsize>>>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            result = listener.accept() => {
                let Ok((stream, _)) = result else { break };
                let responses = responses.clone();
                let counts = counts.clone();
                tokio::spawn(async move { serve_tcp_stream(stream, responses, counts).await; });
            }
        }
    }
}

async fn serve_tcp_stream(
    mut stream: TcpStream,
    responses: Arc<RwLock<HashMap<Key, Fixture>>>,
    counts: Arc<RwLock<HashMap<Key, Arc<AtomicUsize>>>>,
) {
    loop {
        let mut length = [0_u8; 2];
        if stream.read_exact(&mut length).await.is_err() {
            return;
        }
        let length = u16::from_be_bytes(length) as usize;
        let mut request = vec![0_u8; length];
        if stream.read_exact(&mut request).await.is_err() {
            return;
        }
        let Some(response) = response_for(&request, &responses, &counts).await else {
            return;
        };
        let Ok(response) = response.to_vec() else {
            return;
        };
        if response.len() > u16::MAX as usize {
            return;
        }
        if stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .is_err()
            || stream.write_all(&response).await.is_err()
        {
            return;
        }
    }
}

async fn response_for(
    bytes: &[u8],
    responses: &Arc<RwLock<HashMap<Key, Fixture>>>,
    counts: &Arc<RwLock<HashMap<Key, Arc<AtomicUsize>>>>,
) -> Option<Message> {
    let request = Message::from_vec(bytes).ok()?;
    let query = request.queries.first()?;
    let key = (canonical_name(&query.name.to_string()), query.query_type);
    let counter = {
        let mut counts = counts.write().await;
        counts
            .entry(key.clone())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    };
    counter.fetch_add(1, Ordering::Relaxed);
    let fixture = responses.read().await.get(&key).cloned()?;
    if let Fixture::Delayed { delay, .. } = fixture {
        tokio::time::sleep(delay).await;
    }
    fixture.render(&request)
}
