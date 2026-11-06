use hickory_proto::op::{Header, Metadata, ResponseCode};
use hickory_server::server::{Request, ResponseInfo};

/// Creates a standard DNS error response matching the incoming request metadata.
pub fn error_response(request: &Request, response_code: ResponseCode) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = response_code;
    let header = Header {
        metadata,
        counts: Default::default(),
    };
    ResponseInfo::from(header)
}
