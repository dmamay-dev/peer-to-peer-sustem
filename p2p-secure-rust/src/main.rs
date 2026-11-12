use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    env,
    error::Error,
    fs,
    hash::{Hash, Hasher},
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures::StreamExt;
use libp2p::{
    dcutr, gossipsub, identify, identity, kad, mdns, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{io, io::AsyncBufReadExt, select, sync::RwLock, time};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(NetworkBehaviour)]
struct SecureChatBehaviour {
    relay_client: relay::client::Behaviour,
    ping: ping::Behaviour,
    dcutr: dcutr::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

const RECONNECT_BASE_DELAY_SECS: u64 = 1;
const RECONNECT_MAX_DELAY_SECS: u64 = 60;
const HEARTBEAT_MAX_FAILURES: u32 = 3;

#[derive(Debug, Default, Clone)]
struct HeartbeatState {
    consecutive_failures: u32,
    last_success: Option<Instant>,
}

#[derive(Debug, Clone)]
struct ReconnectState {
    attempts: u32,
    next_attempt: Instant,
}

fn reconnect_delay(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(6);
    let seconds = RECONNECT_BASE_DELAY_SECS
        .saturating_mul(1u64 << exponent)
        .min(RECONNECT_MAX_DELAY_SECS);
    Duration::from_secs(seconds)
}

fn schedule_reconnect(
    reconnects: &mut HashMap<PeerId, ReconnectState>,
    peer_id: PeerId,
    immediate: bool,
) {
    let state = reconnects.entry(peer_id).or_insert(ReconnectState {
        attempts: 0,
        next_attempt: Instant::now(),
    });
    state.attempts = state.attempts.saturating_add(1);
    state.next_attempt = if immediate {
        Instant::now()
    } else {
        Instant::now() + reconnect_delay(state.attempts)
    };
}

const MAX_MESSAGE_AGE_MS: u128 = 120_000;
const MAX_FUTURE_SKEW_MS: u128 = 15_000;

#[derive(Clone)]
struct ReplayCache {
    seen: Arc<RwLock<HashMap<(String, String), u128>>>,
}

impl ReplayCache {
    fn new() -> Self {
        Self {
            seen: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn validate_and_record(
        &self,
        envelope: &SignedEnvelope,
        now_ms: u128,
    ) -> Result<(), String> {
        if envelope.timestamp_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
            return Err("часова мітка повідомлення надто далеко в майбутньому".into());
        }
        if now_ms.saturating_sub(envelope.timestamp_ms) > MAX_MESSAGE_AGE_MS {
            return Err("повідомлення прострочене".into());
        }

        // Одна write-блокировка охоплює очищення, перевірку та вставлення.
        // Завдяки цьому два паралельні завдання не можуть одночасно
        // прийняти той самий nonce між окремими contains/insert операціями.
        let mut seen = self.seen.write().await;
        seen.retain(|_, timestamp| {
            now_ms.saturating_sub(*timestamp) <= MAX_MESSAGE_AGE_MS + MAX_FUTURE_SKEW_MS
        });

        let key = (envelope.peer_id.clone(), envelope.nonce.clone());
        if seen.contains_key(&key) {
            return Err("повторне відтворення: nonce уже використано".into());
        }

        seen.insert(key, envelope.timestamp_ms);
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedEnvelope {
    version: u8,
    peer_id: String,
    public_key: String,
    timestamp_ms: u128,
    nonce: String,
    payload: String,
    signature: String,
}

fn load_or_create_identity(path: &Path) -> Result<identity::Keypair, Box<dyn Error>> {
    if path.exists() {
        let bytes = fs::read(path)?;
        let keypair = identity::Keypair::from_protobuf_encoding(&bytes)?;
        return Ok(keypair);
    }

    let keypair = identity::Keypair::generate_ed25519();
    let encoded = keypair.to_protobuf_encoding()?;
    fs::write(path, encoded)?;
    Ok(keypair)
}

fn peer_id_from_public_key(public_key: &identity::PublicKey) -> String {
    // Вимога проєкту: PeerId = SHA-256(Protobuf-подання відкритого ключа).
    hex::encode(Sha256::digest(public_key.encode_protobuf()))
}

fn canonical_bytes(
    version: u8,
    peer_id: &str,
    timestamp_ms: u128,
    nonce: &str,
    payload: &str,
) -> Vec<u8> {
    format!("{version}\n{peer_id}\n{timestamp_ms}\n{nonce}\n{payload}").into_bytes()
}

fn create_envelope(
    keypair: &identity::Keypair,
    payload: String,
) -> Result<SignedEnvelope, Box<dyn Error>> {
    let public_key = keypair.public();
    let peer_id = peer_id_from_public_key(&public_key);
    let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let bytes = canonical_bytes(1, &peer_id, timestamp_ms, &nonce, &payload);
    let signature = keypair.sign(&bytes)?;

    Ok(SignedEnvelope {
        version: 1,
        peer_id,
        public_key: BASE64.encode(public_key.encode_protobuf()),
        timestamp_ms,
        nonce,
        payload,
        signature: BASE64.encode(signature),
    })
}

fn verify_envelope(envelope: &SignedEnvelope) -> Result<identity::PublicKey, String> {
    if envelope.version != 1 {
        return Err("непідтримувана версія конверта".into());
    }

    let public_key_bytes = BASE64
        .decode(&envelope.public_key)
        .map_err(|e| format!("помилка Base64 public key: {e}"))?;
    let public_key = identity::PublicKey::try_decode_protobuf(&public_key_bytes)
        .map_err(|e| format!("некоректний публічний ключ: {e}"))?;

    let expected_peer_id = peer_id_from_public_key(&public_key);
    if envelope.peer_id != expected_peer_id {
        return Err("PeerId не відповідає SHA-256 хешу публічного ключа".into());
    }

    let signature = BASE64
        .decode(&envelope.signature)
        .map_err(|e| format!("помилка Base64 signature: {e}"))?;
    let bytes = canonical_bytes(
        envelope.version,
        &envelope.peer_id,
        envelope.timestamp_ms,
        &envelope.nonce,
        &envelope.payload,
    );

    if !public_key.verify(&bytes, &signature) {
        return Err("підпис Ed25519 недійсний".into());
    }

    Ok(public_key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let identity_path = env::var("IDENTITY_PATH").unwrap_or_else(|_| "node_identity.key".into());
    let identity_key = load_or_create_identity(Path::new(&identity_path))?;
    let public_key = identity_key.public();
    let hashed_peer_id = peer_id_from_public_key(&public_key);
    let network_peer_id = public_key.to_peer_id();

    let signing_key = identity_key.clone();
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            };
            let config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(5))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()?;
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                config,
            )?;
            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            let local_peer_id = key.public().to_peer_id();
            let store = kad::store::MemoryStore::new(local_peer_id);
            let mut kademlia = kad::Behaviour::new(local_peer_id, store);
            kademlia.set_mode(Some(kad::Mode::Server));
            let identify = identify::Behaviour::new(
                identify::Config::new("/secure-p2p/1.0.0".into(), key.public())
                    .with_agent_version("p2p-secure-rust/0.4".into()),
            );
            let dcutr = dcutr::Behaviour::new(local_peer_id);
            Ok(SecureChatBehaviour {
                relay_client,
                ping: ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(Duration::from_secs(20))
                        .with_timeout(Duration::from_secs(10)),
                ),
                dcutr,
                kademlia,
                identify,
                gossipsub,
                mdns,
            })
        })?
        .with_swarm_config(|cfg| {
            // Не закривати неактивні з'єднання. Одне TCP/Noise-з'єднання
            // залишається у connection pool, а Yamux відкриває на ньому
            // багато незалежних логічних підпотоків.
            cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
        })
        .build();

    let topic = gossipsub::IdentTopic::new("secure-p2p-chat-v2");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Спільний runtime-стан оголошується до першого використання.
    let replay_cache = ReplayCache::new();
    let mut connection_pool: HashMap<PeerId, HashSet<libp2p::swarm::ConnectionId>> = HashMap::new();
    let mut reconnects: HashMap<PeerId, ReconnectState> = HashMap::new();
    let mut peer_addresses: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
    let mut heartbeat_states: HashMap<PeerId, HeartbeatState> = HashMap::new();

    // RELAY_ADDR приклад:
    // /ip4/203.0.113.10/tcp/4001/p2p/12D3KooW...
    if let Ok(relay_addr_text) = env::var("RELAY_ADDR") {
        let relay_addr: Multiaddr = relay_addr_text.parse()?;
        swarm.dial(relay_addr.clone())?;
        let mut circuit_addr = relay_addr;
        circuit_addr.push(libp2p::multiaddr::Protocol::P2pCircuit);
        swarm.listen_on(circuit_addr)?;
        info!("Підключення до Circuit Relay та резервування relay-адреси запущено");
    }

    // BOOTSTRAP_ADDR використовується для входу в Kademlia DHT.
    // Адреса має завершуватися /p2p/<PeerId>.
    if let Ok(bootstrap_text) = env::var("BOOTSTRAP_ADDR") {
        let mut bootstrap_addr: Multiaddr = bootstrap_text.parse()?;
        let bootstrap_peer = match bootstrap_addr.pop() {
            Some(libp2p::multiaddr::Protocol::P2p(peer_id)) => peer_id,
            _ => return Err("BOOTSTRAP_ADDR має завершуватися /p2p/<PeerId>".into()),
        };
        peer_addresses
            .entry(bootstrap_peer)
            .or_default()
            .insert(bootstrap_addr.clone());
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&bootstrap_peer, bootstrap_addr.clone());
        swarm.dial(bootstrap_addr.with(libp2p::multiaddr::Protocol::P2p(bootstrap_peer)))?;
        swarm.behaviour_mut().kademlia.bootstrap()?;
        info!(peer_id = %bootstrap_peer, "Kademlia bootstrap запущено");
    }

    println!("Identity file: {identity_path}");
    println!("libp2p network PeerId: {network_peer_id}");
    println!("Application PeerId (SHA-256 public key): {hashed_peer_id}");
    println!("Підпис: Ed25519; Noise XX; persistent connections + Yamux pooling");
    println!("Введіть повідомлення. Ctrl+C для виходу.");

    let mut stdin = io::BufReader::new(io::stdin()).lines();
    let mut reconnect_tick = time::interval(Duration::from_millis(500));
    reconnect_tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        select! {
            _ = reconnect_tick.tick() => {
                let now = Instant::now();
                let due: Vec<PeerId> = reconnects
                    .iter()
                    .filter_map(|(peer_id, state)| {
                        (state.next_attempt <= now).then_some(*peer_id)
                    })
                    .collect();

                for peer_id in due {
                    if connection_pool.get(&peer_id).is_some_and(|connections| !connections.is_empty()) {
                        reconnects.remove(&peer_id);
                        continue;
                    }

                    let attempts = reconnects.get(&peer_id).map_or(1, |state| state.attempts);
                    match swarm.dial(peer_id) {
                        Ok(()) => {
                            info!(%peer_id, attempts, "Автоматичне перепідключення запущено");
                            if let Some(state) = reconnects.get_mut(&peer_id) {
                                state.next_attempt = Instant::now() + reconnect_delay(state.attempts);
                            }
                        }
                        Err(error) => {
                            warn!(%peer_id, attempts, %error, "Не вдалося запустити перепідключення");
                            schedule_reconnect(&mut reconnects, peer_id, false);
                        }
                    }
                }
            }
            line = stdin.next_line() => match line? {
                Some(line) if !line.trim().is_empty() => {
                    let envelope = create_envelope(&signing_key, line)?;
                    let encoded = serde_json::to_vec(&envelope)?;
                    match swarm.behaviour_mut().gossipsub.publish(topic.clone(), encoded) {
                        Ok(message_id) => info!(%message_id, peer_id = %envelope.peer_id, "Підписане повідомлення опубліковано"),
                        Err(error) => error!(%error, "Не вдалося опублікувати повідомлення"),
                    }
                }
                Some(_) => {}
                None => break,
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listen address: {address}/p2p/{}", swarm.local_peer_id());
                }
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, established_in, .. } => {
                    connection_pool.entry(peer_id).or_default().insert(connection_id);
                    let pooled = connection_pool.get(&peer_id).map_or(0, HashSet::len);
                    reconnects.remove(&peer_id);
                    heartbeat_states.entry(peer_id).or_default();
                    info!(%peer_id, ?connection_id, ?established_in, pooled, "Довготривале з'єднання додано до pool; reconnect state скинуто");
                }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => {
                    if let Some(connections) = connection_pool.get_mut(&peer_id) {
                        connections.remove(&connection_id);
                        if connections.is_empty() {
                            connection_pool.remove(&peer_id);
                        }
                    }
                    let has_connections = connection_pool
                        .get(&peer_id)
                        .is_some_and(|connections| !connections.is_empty());
                    if !has_connections {
                        schedule_reconnect(&mut reconnects, peer_id, true);
                        warn!(%peer_id, ?connection_id, ?cause, "Усі з'єднання втрачено; заплановано автоматичне перепідключення");
                    } else {
                        warn!(%peer_id, ?connection_id, ?cause, "Одне з'єднання видалено з pool; резервне ще активне");
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } => {
                    schedule_reconnect(&mut reconnects, peer_id, false);
                    let delay = reconnects.get(&peer_id)
                        .map(|state| reconnect_delay(state.attempts).as_secs())
                        .unwrap_or(RECONNECT_BASE_DELAY_SECS);
                    warn!(%peer_id, %error, retry_in_seconds = delay, "Перепідключення не вдалося; застосовано exponential backoff");
                }
                SwarmEvent::Behaviour(SecureChatBehaviourEvent::Ping(event)) => {
                    match event.result {
                        Ok(_) => {
                            let state = heartbeat_states.entry(event.peer).or_default();

                            state.consecutive_failures = 0;
                            state.last_success = Some(Instant::now());

                            // Pong отримано успішно.
                            // Службове повідомлення не виводиться користувачу.
                        }

                        Err(e) => {
                            let failures = {
                                let state = heartbeat_states.entry(event.peer).or_default();

                                state.consecutive_failures =
                                    state.consecutive_failures.saturating_add(1);

                                state.consecutive_failures
                            };

                            warn!(
                                peer_id = %event.peer,
                                failures,
                                %e,
                                "Heartbeat помилка"
                            );

                            if failures >= HEARTBEAT_MAX_FAILURES {
                                swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .remove_explicit_peer(&event.peer);

                                heartbeat_states.remove(&event.peer);
                                reconnects.remove(&event.peer);

                                let _ = swarm.disconnect_peer_id(event.peer);

                                warn!(
                                    peer_id = %event.peer,
                                    "Вузол видалено після трьох Heartbeat-помилок"
                                );
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(SecureChatBehaviourEvent::Identify(
                    identify::Event::Received { peer_id, info, .. }
                )) => {
                    for address in info.listen_addrs {
                        peer_addresses.entry(peer_id).or_default().insert(address.clone());
                        peer_addresses.entry(peer_id).or_default().insert(address.clone());
                        swarm.add_peer_address(peer_id, address.clone());
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, address);
                    }
                    info!(%peer_id, "Identify-адреси додано до Kademlia");
                }
                SwarmEvent::Behaviour(SecureChatBehaviourEvent::Kademlia(event)) => {
                    info!(?event, "Подія Kademlia DHT");
                }
                SwarmEvent::Behaviour(SecureChatBehaviourEvent::Dcutr(event)) => {
                    info!(?event, "Подія DCUtR hole punching");
                }
                SwarmEvent::Behaviour(SecureChatBehaviourEvent::RelayClient(event)) => {
                    info!(?event, "Подія Circuit Relay");
                }
                SwarmEvent::Behaviour(SecureChatBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                    for (peer_id, address) in peers {
                        info!(%peer_id, %address, "mDNS знайшов вузол");
                        peer_addresses.entry(peer_id).or_default().insert(address.clone());
                        swarm.add_peer_address(peer_id, address.clone());
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, address);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                }
                SwarmEvent::Behaviour(SecureChatBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                    for (peer_id, address) in peers {
                        if let Some(addresses) = peer_addresses.get_mut(&peer_id) {
                            addresses.remove(&address);
                            if addresses.is_empty() {
                                peer_addresses.remove(&peer_id);
                            }
                        }
                        swarm.behaviour_mut().kademlia.remove_address(&peer_id, &address);
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                }
                SwarmEvent::Behaviour(SecureChatBehaviourEvent::Gossipsub(
                    gossipsub::Event::Message { propagation_source, message_id, message }
                )) => {
                    match serde_json::from_slice::<SignedEnvelope>(&message.data) {
                        Ok(envelope) => match verify_envelope(&envelope) {
                            Ok(public_key) => {
                                let now_ms = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map(|d| d.as_millis())
                                    .unwrap_or_default();
                                if let Err(reason) = replay_cache.validate_and_record(&envelope, now_ms).await {
                                    warn!(%propagation_source, %reason, "Повторне або несвіже повідомлення відхилено");
                                    continue;
                                }

                                // Друга перевірка прив'язує ключ конверта до стандартної libp2p identity.
                                if public_key.to_peer_id() != propagation_source {
                                    warn!(%propagation_source, "Ключ конверта не відповідає libp2p PeerId відправника");
                                    continue;
                                }
                                println!("[{}] {}", envelope.peer_id, envelope.payload);
                                info!(%message_id, peer_id = %envelope.peer_id, "Ed25519-підпис і PeerId перевірено");
                            }
                            Err(reason) => warn!(%propagation_source, %reason, "Повідомлення відхилено"),
                        },
                        Err(error) => warn!(%propagation_source, %error, "Некоректний формат підписаного конверта"),
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_and_peer_id_are_verified() {
        let keypair = identity::Keypair::generate_ed25519();
        let envelope = create_envelope(&keypair, "Привіт".into()).unwrap();
        assert!(verify_envelope(&envelope).is_ok());
    }

    #[test]
    fn modified_payload_is_rejected() {
        let keypair = identity::Keypair::generate_ed25519();
        let mut envelope = create_envelope(&keypair, "Оригінал".into()).unwrap();
        envelope.payload = "Підміна".into();
        assert!(verify_envelope(&envelope).is_err());
    }

    #[tokio::test]
    async fn replayed_nonce_is_rejected() {
        let keypair = identity::Keypair::generate_ed25519();
        let envelope = create_envelope(&keypair, "Один раз".into()).unwrap();
        let cache = ReplayCache::new();
        assert!(cache
            .validate_and_record(&envelope, envelope.timestamp_ms)
            .await
            .is_ok());
        assert!(cache
            .validate_and_record(&envelope, envelope.timestamp_ms)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn expired_message_is_rejected() {
        let keypair = identity::Keypair::generate_ed25519();
        let envelope = create_envelope(&keypair, "Старе".into()).unwrap();
        let cache = ReplayCache::new();
        let later = envelope.timestamp_ms + MAX_MESSAGE_AGE_MS + 1;
        assert!(cache.validate_and_record(&envelope, later).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_replay_is_accepted_only_once() {
        let keypair = identity::Keypair::generate_ed25519();
        let envelope = Arc::new(create_envelope(&keypair, "Паралельна перевірка".into()).unwrap());
        let cache = ReplayCache::new();
        let now = envelope.timestamp_ms;

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let envelope = envelope.clone();
            tasks.push(tokio::spawn(async move {
                cache.validate_and_record(&envelope, now).await.is_ok()
            }));
        }

        let mut accepted = 0;
        for task in tasks {
            if task.await.unwrap() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 1);
    }
}
