use std::{net::SocketAddr, convert::Infallible, env};
use hyper::{server::conn::http1, service::service_fn, Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

mod routes;
mod models;
mod entities;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pretty_env_logger::init();

    let addr: SocketAddr = ([0,0,0,0], 8080).into();
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);
    let service = routes::Svc::new(&env::var("PGDSN")?).await?;
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let io = TokioIo::new(tcp);
        let svc_clone = service.clone();
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, svc_clone)
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
