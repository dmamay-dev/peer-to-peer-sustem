use std::{env, error::Error, fs, path::Path};

use futures::StreamExt;
use libp2p::{
    identify, identity, kad, noise, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

fn load_or_create_identity(path: &Path) -> Result<identity::Keypair, Box<dyn Error>> {
    if path.exists() {
        let bytes = fs::read(path)?;
        return Ok(identity::Keypair::from_protobuf_encoding(&bytes)?);
    }

    let keypair = identity::Keypair::generate_ed25519();
    fs::write(path, keypair.to_protobuf_encoding()?)?;
    Ok(keypair)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let port: u16 = env::args()
        .nth(1)
        .unwrap_or_else(|| "4001".into())
        .parse()?;
    let identity_path =
        env::var("RELAY_IDENTITY_PATH").unwrap_or_else(|_| "relay_identity.key".into());
    let key = load_or_create_identity(Path::new(&identity_path))?;
    let peer_id = key.public().to_peer_id();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let local_peer_id = key.public().to_peer_id();
            let store = kad::store::MemoryStore::new(local_peer_id);
            let mut kademlia = kad::Behaviour::new(local_peer_id, store);
            kademlia.set_mode(Some(kad::Mode::Server));

            RelayBehaviour {
                relay: relay::Behaviour::new(local_peer_id, relay::Config::default()),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/secure-p2p-relay/1.0.0".into(),
                    key.public(),
                )),
                kademlia,
            }
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(std::time::Duration::from_secs(u64::MAX))
        })
        .build();

    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{port}").parse()?)?;
    println!("Relay identity file: {identity_path}");
    println!("Relay PeerId: {peer_id}");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Relay address: {address}/p2p/{peer_id}");
            }
            SwarmEvent::Behaviour(event) => info!(?event, "Relay event"),
            _ => {}
        }
    }
}
