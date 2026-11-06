//! Read-only IPv4/IPv6 neighbor discovery. No external command or privileges.
use std::{collections::HashMap, net::IpAddr};

#[cfg(target_os = "linux")]
pub(crate) fn read() -> std::io::Result<HashMap<IpAddr, String>> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::{mem::MaybeUninit, os::fd::AsRawFd, time::Duration};
    let socket = Socket::new(
        Domain::from(libc::AF_NETLINK),
        Type::DGRAM,
        Some(Protocol::from(libc::NETLINK_ROUTE)),
    )?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut request = [0u8; 28];
    request[..4].copy_from_slice(&28u32.to_ne_bytes());
    request[4..6].copy_from_slice(&30u16.to_ne_bytes()); // RTM_GETNEIGH
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    // SAFETY: zero is a valid sockaddr_nl representation; all initialized
    // pointers below remain live for the duration of the synchronous send.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut result = HashMap::new();
    loop {
        let mut bytes = [MaybeUninit::<u8>::uninit(); 65536];
        let length = socket.recv(&mut bytes)?;
        // SAFETY: recv initialized exactly these length bytes.
        let bytes = unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), length) };
        let mut offset = 0;
        while offset + 16 <= bytes.len() {
            let header = &bytes[offset..];
            let length = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
            if length < 16 || offset + length > bytes.len() {
                return Err(std::io::Error::other("Invalid neighbor message"));
            }
            let kind = u16::from_ne_bytes(header[4..6].try_into().unwrap());
            let flags = u16::from_ne_bytes(header[6..8].try_into().unwrap());
            if flags & 0x10 != 0 {
                return Err(std::io::Error::other("Neighbor dump interrupted"));
            }
            if kind == 3 {
                result.retain(|_, mac: &mut String| !mac.is_empty());
                return Ok(result);
            } // NLMSG_DONE
            if kind == 2 {
                return Err(std::io::Error::other("Neighbor dump rejected"));
            }
            if kind == 28
                && let Some((ip, mac)) = parse(&header[..length])
            {
                // Link-local addresses can be repeated on different links.
                // Without an interface-qualified client identity, do not guess.
                result
                    .entry(ip)
                    .and_modify(|previous| {
                        if *previous != mac {
                            previous.clear();
                        }
                    })
                    .or_insert(mac);
            }
            offset += (length + 3) & !3;
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read() -> std::io::Result<HashMap<IpAddr, String>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Neighbor discovery requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn parse(message: &[u8]) -> Option<(IpAddr, String)> {
    if message.len() < 28 {
        return None;
    }
    let family = message[16] as i32;
    let state = u16::from_ne_bytes(message[24..26].try_into().ok()?);
    if state & (0x01 | 0x20) != 0 || state == 0 {
        return None;
    } // INCOMPLETE / FAILED
    let mut ip = None;
    let mut mac = None;
    let mut offset = 28;
    while offset + 4 <= message.len() {
        let attr = &message[offset..];
        let length = u16::from_ne_bytes(attr[..2].try_into().ok()?) as usize;
        if length < 4 || offset + length > message.len() {
            return None;
        }
        let kind = u16::from_ne_bytes(attr[2..4].try_into().ok()?);
        let data = &attr[4..length];
        match (kind, family, data.len()) {
            (1, libc::AF_INET, 4) => {
                ip = Some(IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(data).ok()?,
                )))
            }
            (1, libc::AF_INET6, 16) => {
                ip = Some(IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(data).ok()?,
                )))
            }
            (2, _, 6) if data.iter().any(|&b| b != 0) && data[0] & 1 == 0 => {
                mac = Some(
                    data.iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                )
            }
            _ => {}
        }
        offset += (length + 3) & !3;
    }
    Some((ip?, mac?))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn ipv6_neighbors_and_failed_entries() {
        let mut message = vec![0; 28];
        message[16] = libc::AF_INET6 as u8;
        message[24..26].copy_from_slice(&2u16.to_ne_bytes());
        message.extend_from_slice(&20u16.to_ne_bytes());
        message.extend_from_slice(&1u16.to_ne_bytes());
        message.extend_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        message.extend_from_slice(&10u16.to_ne_bytes());
        message.extend_from_slice(&2u16.to_ne_bytes());
        message.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(
            parse(&message),
            Some(("2001:db8::1".parse().unwrap(), "02:11:22:33:44:55".into()))
        );
        message[24..26].copy_from_slice(&0x20u16.to_ne_bytes());
        assert!(parse(&message).is_none());
        message[24..26].copy_from_slice(&2u16.to_ne_bytes());
        message.truncate(35);
        assert!(parse(&message).is_none());
    }
}
