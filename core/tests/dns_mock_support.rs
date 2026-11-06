mod support;

use std::net::Ipv4Addr;

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use support::{DnsMock, Fixture};

#[tokio::test]
async fn mock_serves_wire_fixtures_over_udp_and_tcp() {
    let mock = DnsMock::start().await.expect("mock binds loopback ports");
    mock.set_fixture(
        "a.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A(Ipv4Addr::new(192, 0, 2, 1)),
            ttl: 30,
        },
    )
    .await;
    mock.set_fixture(
        "aaaa.example.",
        RecordType::AAAA,
        Fixture::PositiveAaaa {
            address: AAAA("2001:db8::1".parse().expect("valid fixture address")),
            ttl: 30,
        },
    )
    .await;

    let mut request = Message::query();
    request.add_query(hickory_proto::op::Query::query(
        "a.example.".parse().expect("valid fixture name"),
        RecordType::A,
    ));
    let request_bytes = request.to_vec().expect("encode request");
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP client");
    socket
        .send_to(&request_bytes, mock.udp_addr())
        .await
        .expect("send UDP request");
    let mut response_bytes = [0_u8; 4096];
    let (length, _) = socket
        .recv_from(&mut response_bytes)
        .await
        .expect("receive UDP response");
    let response = Message::from_bytes(&response_bytes[..length]).expect("decode UDP response");
    assert_eq!(
        response.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
    );

    let mut tcp = TcpStream::connect(mock.tcp_addr())
        .await
        .expect("connect TCP client");
    tcp.write_all(&(request_bytes.len() as u16).to_be_bytes())
        .await
        .expect("write TCP length");
    tcp.write_all(&request_bytes)
        .await
        .expect("write TCP request");
    let mut response_length = [0_u8; 2];
    tcp.read_exact(&mut response_length)
        .await
        .expect("read TCP length");
    let mut response_bytes = vec![0_u8; u16::from_be_bytes(response_length) as usize];
    tcp.read_exact(&mut response_bytes)
        .await
        .expect("read TCP response");
    let response = Message::from_bytes(&response_bytes).expect("decode TCP response");
    assert_eq!(response.answers[0].record_type(), RecordType::A);
    assert_eq!(mock.request_count("a.example", RecordType::A).await, 2);
}
