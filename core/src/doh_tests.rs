use super::*;
use hickory_proto::{
    dnssec::{
        Algorithm, SigningKey, TBS, TrustAnchors,
        crypto::EcdsaSigningKey,
        rdata::{DNSKEY, DNSSECRData, NSEC, RRSIG, sig::SigInput},
    },
    op::{Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType, SerialNumber,
        rdata::{A, SOA},
    },
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) struct SignedZone {
    pub(crate) key: EcdsaSigningKey,
    dnskey: DNSKEY,
}
impl SignedZone {
    pub(crate) fn new() -> Self {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let key = EcdsaSigningKey::from_pkcs8(
            &EcdsaSigningKey::generate_pkcs8(algorithm).unwrap(),
            algorithm,
        )
        .unwrap();
        let dnskey = DNSKEY::from_key(&key.to_public_key().unwrap());
        Self { key, dnskey }
    }
    fn signed(&self, record: Record) -> Vec<Record> {
        let now = crate::config::now_epoch() as u32;
        let input = SigInput {
            type_covered: record.record_type(),
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: record.name.num_labels(),
            original_ttl: record.ttl,
            sig_expiration: SerialNumber::new(
                if record.name == Name::from_ascii("expired.example.").unwrap() {
                    now - 3600
                } else {
                    now + 3600
                },
            ),
            sig_inception: SerialNumber::new(now - 7200),
            key_tag: self.dnskey.calculate_key_tag().unwrap(),
            signer_name: Name::root(),
        };
        let signature = self
            .key
            .sign(
                &TBS::from_input(&record.name, DNSClass::IN, &input, std::iter::once(&record))
                    .unwrap(),
            )
            .unwrap();
        let sig = Record::from_rdata(
            record.name.clone(),
            record.ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, signature))),
        );
        vec![record, sig]
    }
    pub(crate) fn response(&self, request: &Message) -> Message {
        let query = &request.queries[0];

        let mut response = Message::response(request.id, request.op_code);
        response.add_query(query.clone());
        response.metadata.authoritative = true;
        // The AD bit is deliberately misleading for tampered responses.
        response.metadata.authentic_data = true;
        if query.query_type == RecordType::DNSKEY && query.name.is_root() {
            response.answers = self.signed(Record::from_rdata(
                Name::root(),
                300,
                RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
            ));
        } else if query.name == Name::from_ascii("unsigned.example.").unwrap()
            && query.query_type == RecordType::NS
        {
            response.answers = vec![Record::from_rdata(
                query.name.clone(),
                300,
                RData::NS(hickory_proto::rr::rdata::NS(
                    Name::from_ascii("ns.example.").unwrap(),
                )),
            )];
            response.additionals = vec![Record::from_rdata(
                Name::from_ascii("ns.example.").unwrap(),
                300,
                RData::A(A::new(127, 0, 0, 1)),
            )];
        } else if query.name == Name::from_ascii("unsigned.example.").unwrap()
            && query.query_type == RecordType::DS
        {
            response.authorities = self.signed(Record::from_rdata(
                Name::root(),
                300,
                RData::SOA(SOA::new(
                    Name::from_ascii("ns.example.").unwrap(),
                    Name::from_ascii("hostmaster.example.").unwrap(),
                    1,
                    300,
                    300,
                    300,
                    300,
                )),
            ));
            response.authorities.extend(self.signed(Record::from_rdata(
                query.name.clone(),
                300,
                RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                    Name::from_ascii("zzz.").unwrap(),
                    [RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
                ))),
            )));
        } else if query.name == Name::from_ascii("unsigned.example.").unwrap() {
            response.answers = vec![Record::from_rdata(
                query.name.clone(),
                300,
                RData::A(A::new(192, 0, 2, 10)),
            )];
        } else if ["missing.example.", "tampered-denial.example."]
            .iter()
            .any(|name| query.name == Name::from_ascii(name).unwrap())
        {
            response.metadata.response_code = ResponseCode::NXDomain;
            response.authorities = self.signed(Record::from_rdata(
                Name::root(),
                300,
                RData::SOA(SOA::new(
                    Name::from_ascii("ns.example.").unwrap(),
                    Name::from_ascii("hostmaster.example.").unwrap(),
                    1,
                    300,
                    300,
                    300,
                    300,
                )),
            ));
            response.authorities.extend(self.signed(Record::from_rdata(
                Name::root(),
                300,
                RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                    Name::from_ascii("zzz.").unwrap(),
                    [
                        RecordType::SOA,
                        RecordType::NS,
                        RecordType::DNSKEY,
                        RecordType::NSEC,
                        RecordType::RRSIG,
                    ],
                ))),
            )));
        } else {
            response.answers = self.signed(Record::from_rdata(
                query.name.clone(),
                300,
                RData::A(A::new(192, 0, 2, 10)),
            ));
            if query.name == Name::from_ascii("tampered.example.").unwrap() {
                response.answers[0].data = RData::A(A::new(192, 0, 2, 99));
            }
        }
        if query.name == Name::from_ascii("tampered-denial.example.").unwrap() {
            response.authorities[2].ttl = 1;
            response.authorities[2].data = RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_ascii("aaa.").unwrap(),
                [RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
            )));
        }
        response
    }
}

#[tokio::test]
async fn doh_validates_signatures_denials_and_rejects_tampering_despite_ad() {
    let zone = Arc::new(SignedZone::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transport = DohTransport {
        client: Client::builder().no_proxy().build().unwrap(),
        url: format!("http://{}/dns-query", listener.local_addr().unwrap()),
    };
    let mut anchors = TrustAnchors::empty();
    anchors.insert(&zone.key.to_public_key().unwrap());
    let client = DohClient {
        validator: DnssecDnsHandle::with_trust_anchor(transport.clone(), Arc::new(anchors)),
        transport,
    };
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let zone = zone.clone();
            tasks.spawn(async move {
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut buffer = [0; 4096];
                    let length = socket.read(&mut buffer).await.unwrap();
                    assert!(length > 0);
                    bytes.extend_from_slice(&buffer[..length]);
                    if let Some(position) = bytes.windows(4).position(|v| v == b"\r\n\r\n") { break position + 4; }
                };
                let header = String::from_utf8_lossy(&bytes[..header_end]);
                let length: usize = header.lines().find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
                }).unwrap();
                let received = bytes.len() - header_end;
                if received < length {
                    bytes.resize(header_end + length, 0);
                    socket.read_exact(&mut bytes[header_end + received..]).await.unwrap();
                }
                let request = Message::from_bytes(&bytes[header_end..header_end + length]).unwrap();
                let wire = zone.response(&request).to_vec().unwrap();
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", wire.len()).as_bytes()).await.unwrap();
                socket.write_all(&wire).await.unwrap();
            });
        }
    });
    for (name, expected) in [
        ("valid.example.", Some(ResponseCode::NoError)),
        ("tampered.example.", None),
        ("expired.example.", None),
        ("tampered-denial.example.", None),
        ("unsigned.example.", Some(ResponseCode::NoError)),
        ("missing.example.", Some(ResponseCode::NXDomain)),
    ] {
        let mut request = Message::query();
        request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        let result = client.query_validated(request).await;
        if let Some(code) = expected {
            let response = result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(response.response_code, code);
            assert_eq!(response.authentic_data, name != "unsigned.example.");
        } else {
            assert!(result.is_err(), "tampered data must not be served");
        }
    }
    server.abort();
}
