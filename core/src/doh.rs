use std::fmt;
use std::time::Duration;

use futures_util::{StreamExt, stream::BoxStream};
use hickory_proto::op::{DnsRequest, DnsRequestOptions, DnsResponse};
use hickory_proto::op::{Message, MessageType};
use hickory_proto::serialize::binary::BinDecodable;
use hickory_resolver::net::{
    NetError, dnssec::DnssecDnsHandle, runtime::TokioRuntimeProvider, xfer::DnsHandle,
};
use reqwest::Client;
use tracing::debug;

pub const MAX_DOH_MESSAGE_BYTES: usize = 65_535;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DohConfigError {
    InvalidUrl(String),
    ClientBuild(String),
}

impl fmt::Display for DohConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(reason) => write!(f, "invalid DoH URL: {reason}"),
            Self::ClientBuild(reason) => write!(f, "failed to build DoH client: {reason}"),
        }
    }
}

impl std::error::Error for DohConfigError {}

#[derive(Clone)]
pub struct DohClient {
    transport: DohTransport,
    validator: DnssecDnsHandle<DohTransport>,
}

impl fmt::Debug for DohClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DohClient")
            .field("url", &self.transport.url)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct DohTransport {
    client: Client,
    url: String,
}

impl DnsHandle for DohTransport {
    type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let transport = self.clone();
        Box::pin(futures_util::stream::once(async move {
            let wire = request.to_vec()?;
            let response = transport
                .query(&wire)
                .await
                .map_err(|error| NetError::from(error.to_string()))?;
            Ok(DnsResponse::from_message(response)?)
        }))
    }
}

impl DohClient {
    pub fn new(url: String) -> Result<Self, DohConfigError> {
        let parsed = reqwest::Url::parse(&url)
            .map_err(|error| DohConfigError::InvalidUrl(error.to_string()))?;
        if parsed.scheme() != "https" {
            return Err(DohConfigError::InvalidUrl(
                "scheme must be https".to_string(),
            ));
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(DohConfigError::InvalidUrl("host is required".to_string()));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(DohConfigError::InvalidUrl(
                "embedded username/password are not allowed".to_string(),
            ));
        }
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|error| DohConfigError::ClientBuild(error.to_string()))?;
        let transport = DohTransport { client, url };
        let validator = DnssecDnsHandle::new(transport.clone());
        Ok(Self {
            transport,
            validator,
        })
    }

    pub fn url(&self) -> &str {
        &self.transport.url
    }

    pub async fn query_validated(&self, request: Message) -> Result<Message, NetError> {
        let dnssec_ok = request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            self.validator
                .send(DnsRequest::new(request, DnsRequestOptions::default()))
                .next(),
        )
        .await
        .map_err(|_| NetError::from("DoH DNSSEC validation timed out"))?
        .ok_or_else(|| NetError::from("DoH validator returned no response"))?;
        Ok(crate::dnssec::validated_message(result)?.maybe_strip_dnssec_records(dnssec_ok))
    }

    pub async fn query(
        &self,
        request_bytes: &[u8],
    ) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
        self.transport.query(request_bytes).await
    }
}

impl DohTransport {
    /// Queries the DoH server with a DNS wire-format request.
    pub async fn query(
        &self,
        request_bytes: &[u8],
    ) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
        let request = Message::from_bytes(request_bytes)?;
        if request.message_type != MessageType::Query || request.queries.len() != 1 {
            return Err("DoH request must be a single DNS query".into());
        }
        debug!("Sending DoH request to {}", self.url);

        let response = self
            .client
            .post(&self.url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(request_bytes.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("DoH server returned status: {}", response.status()).into());
        }
        if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE) {
            let content_type = content_type.to_str()?;
            let media_type = content_type.split(';').next().unwrap_or_default().trim();
            if !media_type.eq_ignore_ascii_case("application/dns-message") {
                return Err(format!("unexpected DoH content type: {content_type}").into());
            }
        } else {
            return Err("DoH response is missing Content-Type".into());
        }
        if let Some(content_length) = response.content_length()
            && content_length > MAX_DOH_MESSAGE_BYTES as u64
        {
            return Err("DoH response exceeds the DNS wire-size limit".into());
        }

        let mut body = Vec::new();
        let mut response = response;
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_DOH_MESSAGE_BYTES {
                return Err("DoH response exceeds the DNS wire-size limit".into());
            }
            body.extend_from_slice(&chunk);
        }
        let response = Message::from_bytes(&body)?;
        validate_response(&request, response)
    }
}

fn validate_response(
    request: &Message,
    response: Message,
) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
    if response.message_type != MessageType::Response {
        return Err("DoH response is not a DNS response".into());
    }
    if response.metadata.id != request.metadata.id {
        return Err("DoH response transaction ID does not match".into());
    }
    if response.metadata.op_code != request.metadata.op_code {
        return Err("DoH response opcode does not match".into());
    }
    if response.queries.len() != 1 {
        return Err("DoH response must contain exactly one question".into());
    }
    let expected = &request.queries[0];
    let actual = &response.queries[0];
    if actual.name != expected.name
        || actual.query_type != expected.query_type
        || actual.query_class != expected.query_class
    {
        return Err("DoH response question does not match the request".into());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_and_embedded_credentials() {
        assert!(DohClient::new("http://dns.example/dns-query".to_string()).is_err());
        assert!(DohClient::new("https://user:pass@dns.example/dns-query".to_string()).is_err());
        assert!(DohClient::new("https://".to_string()).is_err());
        assert!(DohClient::new("https://dns.example/dns-query".to_string()).is_ok());
    }

    #[test]
    fn rejects_mismatched_dns_response() {
        let mut request = Message::query();
        request.add_query(hickory_proto::op::Query::query(
            "example.com.".parse().unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.add_query(hickory_proto::op::Query::query(
            "other.example.".parse().unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        assert!(validate_response(&request, response).is_err());
    }
}

#[cfg(test)]
#[path = "doh_tests.rs"]
pub(crate) mod validation_tests;
