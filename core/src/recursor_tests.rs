use super::*;
use crate::doh::validation_tests::SignedZone;
use hickory_proto::{dnssec::SigningKey, dnssec::TrustAnchors, op::ResponseCode};

#[tokio::test]
async fn recursive_validation_rejects_tampering_and_preserves_signed_denials() {
    let zone = SignedZone::new();
    // Redirect authoritative port 53 to an unprivileged local fixture.
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut anchors = TrustAnchors::empty();
    anchors.insert(&zone.key.to_public_key().unwrap());
    let mut dnssec = DnssecConfig::default();
    dnssec.trust_anchor = Some(Arc::new(anchors));
    let options = RecursorOptions {
        deny_server: vec![],
        ..RecursorOptions::default()
    };
    let runtime = RedirectRuntime {
        target: socket.local_addr().unwrap(),
        inner: TokioRuntimeProvider::default(),
    };
    let recursor = Recursor::new(
        &[runtime.target.ip()],
        DnssecPolicy::ValidateWithStaticKey(dnssec),
        None,
        options,
        runtime,
    )
    .unwrap();
    let resolver = RecursiveResolver {
        inner: Arc::new(recursor),
        validate: true,
    };
    let server = tokio::spawn(async move {
        let mut bytes = [0; 65535];
        loop {
            let (length, client) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..length]).unwrap();
            socket
                .send_to(&zone.response(&request).to_vec().unwrap(), client)
                .await
                .unwrap();
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
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            resolver.resolve(&Name::from_ascii(name).unwrap(), RecordType::A, false),
        )
        .await
        .unwrap();
        if let Some(code) = expected {
            let response = result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(response.response_code, code);
            assert_eq!(response.authentic_data, name != "unsigned.example.");
        } else {
            assert!(result.is_err(), "{name} must not validate");
        }
    }
    server.abort();
}

use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

#[derive(Clone)]
struct RedirectRuntime {
    target: SocketAddr,
    inner: TokioRuntimeProvider,
}
impl RuntimeProvider for RedirectRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
    type Udp = RedirectUdp;
    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }
    fn connect_tcp(
        &self,
        _server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        self.inner.connect_tcp(self.target, bind, timeout)
    }
    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let target = self.target;
        let future = self.inner.bind_udp(local, server);
        Box::pin(async move {
            Ok(RedirectUdp {
                socket: future.await?,
                target,
            })
        })
    }
}
struct RedirectUdp {
    socket: tokio::net::UdpSocket,
    target: SocketAddr,
}
#[async_trait::async_trait]
impl DnsUdpSocket for RedirectUdp {
    type Time = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        _target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.socket.poll_send_to(cx, bytes, self.target)
    }
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        DnsUdpSocket::poll_recv_from(&self.socket, cx, bytes).map_ok(|(length, mut source)| {
            source.set_port(53);
            (length, source)
        })
    }
}
