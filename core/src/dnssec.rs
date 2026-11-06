//! Apply local validation results, rather than trusting an upstream AD bit.
use hickory_proto::{
    dnssec::{DnssecSummary, Proof},
    op::{DnsResponse, Message, ResponseCode},
    rr::RecordType,
};
use hickory_resolver::net::{DnsError, NetError};

pub(crate) fn validated_message(
    result: Result<DnsResponse, NetError>,
) -> Result<Message, NetError> {
    let response = match result {
        Ok(response) => response,
        Err(NetError::Dns(DnsError::Nsec {
            response,
            proof: Proof::Secure | Proof::Insecure,
            ..
        })) => *response,
        Err(NetError::Dns(DnsError::NoRecordsFound(records))) => {
            let mut message = Message::response(0, hickory_proto::op::OpCode::Query);
            message.metadata.response_code = records.response_code;
            message.add_query(*records.query);
            if let Some(soa) = records.soa {
                message.add_authority(soa.into_record_of_rdata());
            }
            if let Some(authorities) = records.authorities {
                message.authorities.extend(authorities.iter().cloned());
            }
            DnsResponse::from_message(message)?
        }
        Err(error) => return Err(error),
    };
    enforce_proofs(response.into_message())
}

pub(crate) fn enforce_proofs(mut message: Message) -> Result<Message, NetError> {
    if !matches!(
        message.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return Err(NetError::from(
            "DNSSEC upstream returned an unsuccessful response",
        ));
    }
    let records = if message.answers.is_empty() {
        &message.authorities
    } else {
        &message.answers
    };
    // Additional glue is not signed. RRSIG proof belongs to the RRset it
    // covers; unused signatures need not independently validate.
    let relevant = records
        .iter()
        .filter(|rr| rr.record_type() != RecordType::RRSIG);
    if relevant
        .clone()
        .any(|rr| !matches!(rr.proof, Proof::Secure | Proof::Insecure))
    {
        return Err(NetError::Dns(DnsError::DnssecBogus));
    }
    if relevant.clone().next().is_none() {
        return Err(NetError::from(
            "DNSSEC response has no authenticated answer or denial",
        ));
    }
    // Optional authority/additional data must not smuggle unverified records
    // into a validated answer. Negative authority data was required above.
    if !message.answers.is_empty() {
        message
            .authorities
            .retain(|record| matches!(record.proof, Proof::Secure | Proof::Insecure));
    }
    message
        .additionals
        .retain(|record| matches!(record.proof, Proof::Secure | Proof::Insecure));
    message.metadata.authentic_data = matches!(
        DnssecSummary::from_records(message.answers.iter().chain(message.authorities.iter())),
        DnssecSummary::Secure
    );
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, RData, Record, rdata::A};

    #[test]
    fn unverified_optional_records_cannot_ride_a_validated_answer() {
        let mut message = Message::response(1, hickory_proto::op::OpCode::Query);
        let mut valid = Record::from_rdata(
            Name::from_ascii("valid.example.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 10)),
        );
        valid.proof = Proof::Secure;
        message.answers.push(valid.clone());
        let mut unverified = valid;
        unverified.proof = Proof::Bogus;
        message.authorities.push(unverified.clone());
        unverified.proof = Proof::Indeterminate;
        message.additionals.push(unverified);
        let result = enforce_proofs(message).unwrap();
        assert!(result.authentic_data);
        assert!(result.authorities.is_empty());
        assert!(result.additionals.is_empty());
    }
}
