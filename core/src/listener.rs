use crate::handler::DnsHandler;
use hickory_server::Server;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tracing::{error, info};

fn create_udp_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

fn create_tcp_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

pub async fn run_server(
    addr: SocketAddr,
    handler: DnsHandler,
    num_workers: usize,
) -> std::io::Result<()> {
    info!("Starting server on {} with {} workers", addr, num_workers);

    let mut tasks = Vec::new();

    for worker_id in 0..num_workers {
        let handler_clone = handler.clone();

        let udp_socket = create_udp_socket(addr)?;
        let tcp_listener = create_tcp_listener(addr)?;

        let task = tokio::spawn(async move {
            info!("Worker {} starting", worker_id);
            let mut server = Server::new(handler_clone);

            server.register_socket(udp_socket);
            server.register_listener(tcp_listener, Duration::from_secs(30), 1024);

            server
                .block_until_done()
                .await
                .map_err(|error| format!("server error: {error:?}"))
                .and_then(|()| Err("server stopped normally".to_string()))
        });

        tasks.push(task);
    }

    await_workers(tasks).await
}

// Any worker exit is abnormal: report errors so a supervisor can restart
// a process that can no longer serve DNS. Await every worker to retain diagnostics.
async fn await_workers(
    tasks: Vec<tokio::task::JoinHandle<Result<(), String>>>,
) -> std::io::Result<()> {
    let mut workers = JoinSet::new();
    for (worker_id, task) in tasks.into_iter().enumerate() {
        workers.spawn(async move { (worker_id, task.await) });
    }

    let Some(first) = workers.join_next().await else {
        return Ok(());
    };
    let failure = match first {
        Ok((worker_id, Ok(Ok(())))) => {
            format!("DNS listener worker {worker_id} exited unexpectedly")
        }
        Ok((worker_id, Ok(Err(cause)))) => {
            format!("DNS listener worker {worker_id} failed: {cause}")
        }
        Ok((worker_id, Err(join_error))) => {
            format!("DNS listener worker {worker_id} panicked or was cancelled: {join_error}")
        }
        Err(join_error) => format!("DNS listener supervisor failed: {join_error}"),
    };
    error!("{}", failure);
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    Err(std::io::Error::other(failure))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_await_workers_errors_when_a_worker_returns_normally() {
        // There is no graceful shutdown path; even an Ok worker exit must fail the server.
        let tasks: Vec<tokio::task::JoinHandle<Result<(), String>>> =
            vec![tokio::spawn(async { Ok::<(), String>(()) })];
        assert!(await_workers(tasks).await.is_err());
    }

    #[tokio::test]
    async fn test_await_workers_errors_on_panic() {
        let tasks: Vec<tokio::task::JoinHandle<Result<(), String>>> =
            vec![tokio::spawn(async { panic!("simulated worker crash") })];
        assert!(await_workers(tasks).await.is_err());
    }

    #[tokio::test]
    async fn test_await_workers_checks_every_task_not_just_the_first() {
        // A panicking worker must not stop the rest from being awaited /
        // logged — all workers should be checked.
        let tasks: Vec<tokio::task::JoinHandle<Result<(), String>>> = vec![
            tokio::spawn(async { panic!("first worker crash") }),
            tokio::spawn(async { Ok::<(), String>(()) }),
        ];
        assert!(await_workers(tasks).await.is_err());
    }

    #[tokio::test]
    async fn test_later_worker_failure_is_observed_without_waiting_for_worker_zero() {
        let tasks: Vec<tokio::task::JoinHandle<Result<(), String>>> = vec![
            tokio::spawn(async { std::future::pending::<Result<(), String>>().await }),
            tokio::spawn(async { Err::<(), String>("worker failed".to_string()) }),
        ];
        let result = tokio::time::timeout(Duration::from_millis(100), await_workers(tasks)).await;
        assert!(result.expect("worker failure should be prompt").is_err());
    }
}
