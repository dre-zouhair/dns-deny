use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::net::runtime::{RuntimeProvider, TokioRuntimeProvider};
use hickory_resolver::recursor::{
    DnssecConfig, DnssecPolicy, Recursor, RecursorError, RecursorOptions,
};

const ROOT_HINTS: [&str; 13] = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
];

#[derive(Clone)]
pub struct RecursiveResolver<P: RuntimeProvider = TokioRuntimeProvider> {
    inner: Arc<Recursor<P>>,
    validate: bool,
}

impl RecursiveResolver {
    pub fn new(dnssec_validation: bool) -> Result<Self, RecursorError> {
        let roots: Vec<IpAddr> = ROOT_HINTS
            .iter()
            .map(|address| address.parse().expect("static root hint is a valid IP"))
            .collect();
        let policy = if dnssec_validation {
            DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default())
        } else {
            DnssecPolicy::SecurityUnaware
        };
        Self::with_roots(
            &roots,
            policy,
            RecursorOptions::default(),
            dnssec_validation,
        )
    }

    fn with_roots(
        roots: &[IpAddr],
        policy: DnssecPolicy,
        options: RecursorOptions,
        dnssec_validation: bool,
    ) -> Result<Self, RecursorError> {
        let recursor = Recursor::new(
            roots,
            policy,
            None,
            options,
            TokioRuntimeProvider::default(),
        )?;
        Ok(Self {
            inner: Arc::new(recursor),
            validate: dnssec_validation,
        })
    }
}

impl<P: RuntimeProvider> RecursiveResolver<P> {
    pub async fn resolve(
        &self,
        name: &Name,
        qtype: RecordType,
        dnssec_ok: bool,
    ) -> Result<Message, RecursorError> {
        let result = self
            .inner
            .resolve(
                Query::query(name.clone(), qtype),
                Instant::now(),
                dnssec_ok || self.validate,
            )
            .await;
        if !self.validate {
            return result.map(|mut message| {
                message.metadata.authentic_data = false;
                message
            });
        }
        let validated = match result {
            Ok(message) => crate::dnssec::enforce_proofs(message),
            Err(RecursorError::Net(error)) => crate::dnssec::validated_message(Err(error)),
            Err(error) => return Err(error),
        }
        .map_err(RecursorError::Net)?;
        Ok(validated.maybe_strip_dnssec_records(dnssec_ok))
    }
}

#[cfg(test)]
mod tests {
    use super::RecursiveResolver;

    #[test]
    fn constructs_security_unaware_and_dnssec_recursor() {
        assert!(RecursiveResolver::new(false).is_ok());
        assert!(RecursiveResolver::new(true).is_ok());
    }
}

#[cfg(test)]
#[path = "recursor_tests.rs"]
mod validation_tests;
