# Secure P2P Chat на Rust

Повноцінна консольна P2P-програма на `rust-libp2p` для захищеного обміну повідомленнями.

## Реалізовано

- TCP + Noise XX;
- довготривалі з'єднання та Yamux-мультиплексування;
- Gossipsub-чат;
- Ed25519 identity і додатковий Ed25519-підпис прикладного конверта;
- Application PeerId як SHA-256 від Protobuf-подання публічного ключа;
- потокобезпечний replay-cache, nonce і часові обмеження;
- Heartbeat Ping/Pong;
- автоматичне видалення невідповідаючих адрес;
- автоматичне перепідключення з exponential backoff;
- mDNS для локальної мережі;
- Kademlia DHT та Identify;
- Circuit Relay і DCUtR для вузлів за NAT;
- постійні identity-файли, тому PeerId не змінюється після перезапуску;
- окремий relay/DHT bootstrap сервер.

## Вимоги

- актуальний stable Rust;
- відкритий TCP-порт для публічного relay-сервера;
- два термінали для локальної перевірки.

## Перевірка проєкту

```bash
cargo fmt
cargo check
cargo test
```

## Локальний запуск без relay

У першому терміналі:

```bash
RUST_LOG=info IDENTITY_PATH=node-a.key cargo run --bin p2p-secure-rust
```

У другому:

```bash
RUST_LOG=info IDENTITY_PATH=node-b.key cargo run --bin p2p-secure-rust
```

У PowerShell:

```powershell
$env:RUST_LOG="info"
$env:IDENTITY_PATH="node-a.key"
cargo run --bin p2p-secure-rust
```

```powershell
$env:RUST_LOG="info"
$env:IDENTITY_PATH="node-b.key"
cargo run --bin p2p-secure-rust
```

mDNS знайде вузли в одній локальній мережі. Введіть текст і натисніть Enter.

## Запуск relay і DHT bootstrap

```bash
RUST_LOG=info RELAY_IDENTITY_PATH=relay.key cargo run --bin relay_server -- 4001
```

Скопіюйте надруковану адресу:

```text
/ip4/PUBLIC_IP/tcp/4001/p2p/RELAY_PEER_ID
```

Запуск клієнта через relay:

```bash
RELAY_ADDR=/ip4/PUBLIC_IP/tcp/4001/p2p/RELAY_PEER_ID \
BOOTSTRAP_ADDR=/ip4/PUBLIC_IP/tcp/4001/p2p/RELAY_PEER_ID \
IDENTITY_PATH=node-a.key \
RUST_LOG=info \
cargo run --bin p2p-secure-rust
```

PowerShell:

```powershell
$env:RELAY_ADDR="/ip4/PUBLIC_IP/tcp/4001/p2p/RELAY_PEER_ID"
$env:BOOTSTRAP_ADDR=$env:RELAY_ADDR
$env:IDENTITY_PATH="node-a.key"
$env:RUST_LOG="info"
cargo run --bin p2p-secure-rust
```

## Стійка identity

`IDENTITY_PATH` і `RELAY_IDENTITY_PATH` містять приватні ключі. Не публікуйте ці файли та не додавайте їх у Git. Якщо файл уже існує, програма завантажує ключ. Якщо файла немає, створюється новий Ed25519-ключ.

## Heartbeat

- інтервал Ping: 20 секунд;
- timeout Pong: 10 секунд;
- поріг видалення peer: 3 послідовні помилки.

## Автоматичне перепідключення

Затримка між спробами: 1, 2, 4, 8, 16, 32, 60 секунд. Після успішного підключення стан backoff скидається.

## Структура

```text
src/main.rs                основний P2P-клієнт і чат
src/bin/relay_server.rs    Circuit Relay + Kademlia bootstrap
Cargo.toml                 залежності
.env.example               приклад конфігурації
```
