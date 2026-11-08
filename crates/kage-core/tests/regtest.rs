//! Differential tests: `kage-core` vs the reference wallet (wallet2, via
//! `monero-wallet-rpc`) on a private regtest chain (ADR-016).
//!
//! Requires the official Monero CLI binaries (signature-verified in CI):
//!   ZT_MONERO_BIN=/path/to/monero-x86_64-linux-gnu-v0.18.x \
//!     cargo test -p kage-core --features regtest --test regtest -- --nocapture
//!
//! The test FAILS (never skips) if the binaries are missing, so CI cannot
//! pass silently.
//!
//! The spend key used to sign here is a throwaway regtest wallet's key, read
//! from `monero-wallet-rpc`. That exercises exactly what the signer will do
//! in Stage 4: build `SignableTransaction::new` from a `TxIntent`, then sign.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::print_stdout
)]
#![allow(clippy::disallowed_methods)] // spawning monerod/monero-wallet-rpc is the point of this test
#![allow(clippy::disallowed_types)] // binding port 0 to find free ports for the daemons

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use kage_core::Network;
use kage_core::balance::balance;
use kage_core::intent::{SendRequest, build_intent};
use kage_core::keys::ViewKeys;
use kage_core::monero_wallet::address::MoneroAddress;
use kage_core::monero_wallet::ed25519::Scalar;
use kage_core::monero_wallet::interface::{FeePriority, PublishTransaction as _};
use kage_core::monero_wallet::send::{Change, SignableTransaction};
use kage_core::payload::{KeyImageEntry, Payment, TxIntent};
use kage_core::state::WalletState;
use kage_core::sync::sync;
use kage_node::policy::{Endpoint, Host, Ownership, Transport};
use kage_node::transport::{NodeTransport, loopback_for_tests};
use kage_node::{Node, NodeConfig};
use serde_json::{Value, json};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Process harness

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Env {
    _daemon: Proc,
    _wallet_rpc: Proc,
    _dir: PathBuf,
    daemon_port: u16,
    daemon_http: NodeTransport,
    wallet_http: NodeTransport,
}

fn bin_dir() -> PathBuf {
    let p = std::env::var("ZT_MONERO_BIN").expect(
        "ZT_MONERO_BIN must point at the verified Monero CLI binaries (see this file's header)",
    );
    PathBuf::from(p)
}

async fn rpc(t: &NodeTransport, route: &str, body: Value) -> Value {
    let raw = t
        .post_raw(
            route,
            serde_json::to_vec(&body).unwrap(),
            Some(64 * 1024 * 1024),
        )
        .await
        .unwrap_or_else(|e| panic!("{route}: {e}"));
    serde_json::from_slice(&raw).unwrap()
}

async fn json_rpc(t: &NodeTransport, method: &str, params: Value) -> Value {
    let v = rpc(
        t,
        "json_rpc",
        json!({"jsonrpc":"2.0","id":0,"method":method,"params":params}),
    )
    .await;
    if let Some(e) = v.get("error") {
        panic!("{method}: {e}");
    }
    v["result"].clone()
}

async fn start() -> Env {
    let bin = bin_dir();
    let dir =
        std::env::temp_dir().join(format!("zt-regtest-{}-{}", std::process::id(), free_port()));
    std::fs::create_dir_all(dir.join("wallets")).unwrap();
    let daemon_port = free_port();
    let wallet_port = free_port();

    let daemon = Proc(
        Command::new(bin.join("monerod"))
            .args([
                "--regtest",
                "--offline",
                "--fixed-difficulty",
                "1",
                "--non-interactive",
                "--no-zmq",
            ])
            .args([
                "--rpc-bind-ip",
                "127.0.0.1",
                "--rpc-bind-port",
                &daemon_port.to_string(),
            ])
            .args(["--p2p-bind-port", &free_port().to_string()])
            .arg("--data-dir")
            .arg(dir.join("chain"))
            .args(["--log-level", "0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn monerod"),
    );
    let daemon_http = loopback_for_tests(daemon_port);
    for _ in 0..60 {
        if daemon_http
            .post_raw("get_info", b"{}".to_vec(), Some(1 << 16))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let wallet_rpc = Proc(
        Command::new(bin.join("monero-wallet-rpc"))
            .args(["--daemon-address", &format!("127.0.0.1:{daemon_port}")])
            .args([
                "--trusted-daemon",
                "--allow-mismatched-daemon-version",
                "--disable-rpc-login",
            ])
            .args([
                "--rpc-bind-ip",
                "127.0.0.1",
                "--rpc-bind-port",
                &wallet_port.to_string(),
            ])
            .arg("--wallet-dir")
            .arg(dir.join("wallets"))
            .arg("--shared-ringdb-dir")
            .arg(dir.join("ringdb"))
            .args(["--non-interactive", "--log-level", "0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn monero-wallet-rpc"),
    );
    let wallet_http = loopback_for_tests(wallet_port);
    for _ in 0..60 {
        let ok = wallet_http
            .post_raw(
                "json_rpc",
                br#"{"jsonrpc":"2.0","id":0,"method":"get_version"}"#.to_vec(),
                Some(1 << 16),
            )
            .await
            .is_ok();
        if ok {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Env {
        _daemon: daemon,
        _wallet_rpc: wallet_rpc,
        _dir: dir,
        daemon_port,
        daemon_http,
        wallet_http,
    }
}

impl Env {
    async fn mine(&self, n: u64, to: &str) {
        json_rpc(
            &self.daemon_http,
            "generateblocks",
            json!({"amount_of_blocks": n, "wallet_address": to}),
        )
        .await;
    }
    async fn w(&self, method: &str, params: Value) -> Value {
        json_rpc(&self.wallet_http, method, params).await
    }
    async fn open(&self, name: &str) {
        self.w("open_wallet", json!({"filename": name})).await;
        self.w("refresh", json!({})).await;
    }
    async fn node(&self) -> Node {
        let ep = Endpoint {
            host: Host::Ip(std::net::IpAddr::from([127, 0, 0, 1])),
            port: self.daemon_port,
            transport: Transport::Direct,
            ownership: Ownership::Own,
        };
        Node::connect(&NodeConfig::new(ep, Network::Regtest), None)
            .await
            .expect("connect node")
    }
    async fn tip(&self) -> u64 {
        json_rpc(&self.daemon_http, "get_block_count", json!({})).await["count"]
            .as_u64()
            .unwrap()
            - 1
    }
}

/// Opens wallet `name` in wallet-rpc and builds our view-only twin of it.
async fn view_twin(env: &Env, name: &str) -> (ViewKeys, String) {
    env.open(name).await;
    let addr = env.w("get_address", json!({"account_index": 0})).await["address"]
        .as_str()
        .unwrap()
        .to_owned();
    let vk_hex = env.w("query_key", json!({"key_type": "view_key"})).await["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&hex::decode(vk_hex).unwrap());
    let keys =
        ViewKeys::from_address_and_view_key(Network::Regtest, &addr, &mut vk).expect("view keys");
    (keys, addr)
}

/// The reference wallet's view of outputs: `(tx_hash, global_index, amount, account, minor)`.
async fn reference_outputs(env: &Env, accounts: u32) -> BTreeSet<(String, u64, u64, u32, u32)> {
    let mut out = BTreeSet::new();
    for a in 0..accounts {
        let r = env
            .w(
                "incoming_transfers",
                json!({"transfer_type": "all", "account_index": a}),
            )
            .await;
        for t in r["transfers"].as_array().cloned().unwrap_or_default() {
            out.insert((
                t["tx_hash"].as_str().unwrap().to_owned(),
                t["global_index"].as_u64().unwrap(),
                t["amount"].as_u64().unwrap(),
                u32::try_from(t["subaddr_index"]["major"].as_u64().unwrap()).unwrap(),
                u32::try_from(t["subaddr_index"]["minor"].as_u64().unwrap()).unwrap(),
            ));
        }
    }
    out
}

fn our_outputs(state: &WalletState) -> BTreeSet<(String, u64, u64, u32, u32)> {
    state
        .outputs
        .iter()
        .map(|o| {
            let (a, i) = o.subaddress();
            (
                hex::encode(o.output.transaction()),
                o.output.index_on_blockchain(),
                o.amount(),
                a,
                i,
            )
        })
        .collect()
}

/// Key images as wallet2 computed them (output pubkey → key image).
async fn reference_key_images(env: &Env, accounts: u32) -> Vec<KeyImageEntry> {
    let mut v = Vec::new();
    for a in 0..accounts {
        let r = env
            .w(
                "incoming_transfers",
                json!({"transfer_type": "all", "account_index": a}),
            )
            .await;
        for t in r["transfers"].as_array().cloned().unwrap_or_default() {
            let mut output_key = [0u8; 32];
            output_key.copy_from_slice(&hex::decode(t["pubkey"].as_str().unwrap()).unwrap());
            let mut key_image = [0u8; 32];
            key_image.copy_from_slice(&hex::decode(t["key_image"].as_str().unwrap()).unwrap());
            v.push(KeyImageEntry {
                output_key,
                key_image,
            });
        }
    }
    v
}

async fn reference_balance(env: &Env, account: u32) -> (u64, u64) {
    let b = env
        .w("get_balance", json!({"account_index": account}))
        .await;
    (
        b["balance"].as_u64().unwrap(),
        b["unlocked_balance"].as_u64().unwrap(),
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn differential_against_wallet2() {
    let env = start().await;

    // Wallets: A (miner, spends), B (receives on subaddresses / 2 accounts), C (burn).
    for n in ["a", "b", "c"] {
        env.w(
            "create_wallet",
            json!({"filename": n, "language": "English"}),
        )
        .await;
    }
    env.open("c").await;
    let burn = env.w("get_address", json!({"account_index": 0})).await["address"]
        .as_str()
        .unwrap()
        .to_owned();

    env.open("b").await;
    for _ in 0..3 {
        env.w("create_address", json!({"account_index": 0})).await;
    }
    env.w("create_account", json!({"label": "second"})).await;
    env.w("create_address", json!({"account_index": 1})).await;
    let b_addrs = env.w("get_address", json!({"account_index": 0})).await;
    let b_acc1 = env.w("get_address", json!({"account_index": 1})).await;

    let (a_keys, a_addr) = view_twin(&env, "a").await;
    env.mine(120, &a_addr).await;
    env.mine(70, &burn).await; // unlock A's coinbase

    // ---- 1. Address derivation -----------------------------------------
    let (b_keys, b_addr) = view_twin(&env, "b").await;
    for entry in b_addrs["addresses"].as_array().unwrap() {
        let i = u32::try_from(entry["address_index"].as_u64().unwrap()).unwrap();
        assert_eq!(
            b_keys.address(0, i).to_string(),
            entry["address"].as_str().unwrap(),
            "B (0,{i})"
        );
    }
    for entry in b_acc1["addresses"].as_array().unwrap() {
        let i = u32::try_from(entry["address_index"].as_u64().unwrap()).unwrap();
        assert_eq!(
            b_keys.address(1, i).to_string(),
            entry["address"].as_str().unwrap(),
            "B (1,{i})"
        );
    }
    println!(
        "[1] address derivation matches wallet2 ({} addresses)",
        4 + 2
    );

    // ---- A pays B on several subaddresses (wallet2 builds these) --------
    env.open("a").await;
    let dests: Vec<(String, u64)> = vec![
        (b_addr.clone(), 1_000_000_000_000),
        (b_keys.address(0, 2).to_string(), 2_500_000_000_000),
        (b_keys.address(1, 1).to_string(), 700_000_000_000),
    ];
    for (addr, amount) in &dests {
        env.w(
            "transfer",
            json!({"destinations": [{"address": addr, "amount": amount}]}),
        )
        .await;
        env.mine(1, &burn).await;
    }
    env.mine(12, &burn).await;

    let mut node = env.node().await;
    assert_eq!(node.info().nettype, "fakechain");

    // ---- 2. Scanning B: outputs and balances ----------------------------
    let mut b_state = WalletState::new(Network::Regtest, 0);
    let t0 = std::time::Instant::now();
    let rep = sync(&mut b_state, &b_keys, node.daemon(), |_| {})
        .await
        .expect("sync B");
    println!("    B synced in {:?}", t0.elapsed());
    env.open("b").await;
    assert_eq!(
        our_outputs(&b_state),
        reference_outputs(&env, 2).await,
        "B outputs differ from wallet2"
    );
    let chain_height = env.tip().await + 1;
    for acc in 0..2 {
        let ours = balance(&b_state, Some(acc), chain_height, now());
        assert_eq!(
            (ours.total, ours.unlocked),
            reference_balance(&env, acc).await,
            "B account {acc}"
        );
    }
    println!(
        "[2] B: {} outputs over {} blocks; outputs and balances match wallet2",
        b_state.outputs.len(),
        rep.blocks
    );

    // ---- 3. Scanning A, then private spend detection via key images -----
    let mut a_state = WalletState::new(Network::Regtest, 0);
    sync(&mut a_state, &a_keys, node.daemon(), |_| {})
        .await
        .expect("sync A");
    env.open("a").await;
    assert_eq!(
        our_outputs(&a_state),
        reference_outputs(&env, 1).await,
        "A outputs differ"
    );
    let before = balance(&a_state, Some(0), chain_height, now());
    let (ref_total, ref_unlocked) = reference_balance(&env, 0).await;
    assert!(before.unverified_outputs > 0);
    assert!(
        before.total > ref_total,
        "without key images, spends are invisible (expected)"
    );

    let kis = reference_key_images(&env, 1).await;
    assert_eq!(a_state.import_key_images(&kis), a_state.outputs.len());
    let after = balance(&a_state, Some(0), chain_height, now());
    assert_eq!(
        (after.total, after.unlocked),
        (ref_total, ref_unlocked),
        "A balance after key images"
    );
    assert_eq!(after.unverified_outputs, 0);
    let r = env
        .w(
            "incoming_transfers",
            json!({"transfer_type": "all", "account_index": 0}),
        )
        .await;
    for t in r["transfers"].as_array().unwrap() {
        let key = hex::decode(t["pubkey"].as_str().unwrap()).unwrap();
        let o = a_state
            .outputs
            .iter()
            .find(|o| o.key().as_slice() == key.as_slice())
            .unwrap();
        assert_eq!(
            o.spent().is_some(),
            t["spent"].as_bool().unwrap(),
            "spent flag of {}",
            t["pubkey"]
        );
    }
    println!(
        "[3] A: {} outputs; spend detection from ring appearances matches wallet2 after key-image import",
        a_state.outputs.len()
    );

    // ---- 4. Unsigned intent → (signer-equivalent) sign → broadcast ------
    let dest = b_keys.address(0, 3);
    let amount = 1_234_500_000_000u64;
    let req = SendRequest {
        account: 0,
        payments: vec![Payment {
            address: dest,
            amount,
        }],
        priority: FeePriority::Normal,
    };
    let t0 = std::time::Instant::now();
    let built = match build_intent(&a_state, &a_keys, node.daemon(), &req, now()).await {
        Ok(b) => b,
        Err(e) => panic!("build_intent failed: {e} ({e:?})"),
    };
    println!("    intent built in {:?}", t0.elapsed());

    // Round-trip the intent through its wire format, as across the air gap.
    let wire = built.intent.encode(Network::Regtest).unwrap();
    let intent = TxIntent::decode(&wire, Network::Regtest).unwrap();
    assert_eq!(intent, built.intent);
    for input in &intent.inputs {
        assert_eq!(input.decoys().len(), 16, "ring size");
    }

    // What the signer will do (Stage 4): build from the intent, sign.
    let spend_hex = env.w("query_key", json!({"key_type": "spend_key"})).await["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let spend =
        Zeroizing::new(Scalar::read(&mut hex::decode(spend_hex).unwrap().as_slice()).unwrap());
    let mut ovk = Zeroizing::new([0u8; 32]);
    getrandom::fill(ovk.as_mut()).unwrap();
    let stx = SignableTransaction::new(
        intent.rct_type,
        ovk,
        intent.inputs.clone(),
        intent
            .payments
            .iter()
            .map(|p| (p.address, p.amount))
            .collect(),
        Change::new(a_keys.view_pair(), intent.change),
        vec![],
        intent.fee_rate,
    )
    .unwrap();
    assert_eq!(
        stx.necessary_fee(),
        built.fee,
        "fee must be what core showed"
    );
    let tx = stx.sign(&mut rand_core::OsRng, &spend).expect("sign");
    let our_weight = u64::try_from(tx.weight()).unwrap();
    node.daemon()
        .publish_transaction(&tx)
        .await
        .expect("daemon accepted our transaction");
    env.mine(12, &burn).await;

    // wallet2 (B) must see the payment on (0,3).
    env.open("b").await;
    let got = env
        .w("get_transfers", json!({"in": true, "account_index": 0}))
        .await;
    let hash = hex::encode(tx.hash());
    let seen = got["in"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["txid"] == hash)
        .expect("B sees our tx");
    assert_eq!(seen["amount"].as_u64().unwrap(), amount);
    assert_eq!(seen["subaddr_index"]["minor"].as_u64().unwrap(), 3);

    // Fee formula vs wallet2: same fee rate → same fee for the same weight.
    env.open("a").await;
    let w2 = env
        .w("transfer", json!({"destinations": [{"address": dest.to_string(), "amount": amount}], "priority": 2, "do_not_relay": true, "get_tx_metadata": true}))
        .await;
    let w2_fee = w2["fee"].as_u64().unwrap();
    let w2_weight = w2["weight"].as_u64().unwrap();
    let expected_w2_fee =
        u64::try_from(intent.fee_rate.calculate_fee_from_weight(w2_weight)).unwrap();
    assert_eq!(
        w2_fee, expected_w2_fee,
        "wallet2's fee uses the same fee rate we fetched"
    );
    println!(
        "[4] intent → sign → broadcast accepted; B received {amount}; fee {} for weight {our_weight} (wallet2: {w2_fee} for {w2_weight})",
        built.fee
    );

    // ---- 5. After the spend: A's view wallet still matches wallet2 ------
    sync(&mut a_state, &a_keys, node.daemon(), |_| {})
        .await
        .expect("resync A");
    a_state.import_key_images(&reference_key_images(&env, 1).await);
    let chain_height = env.tip().await + 1;
    let ours = balance(&a_state, Some(0), chain_height, now());
    assert_eq!(
        (ours.total, ours.unlocked),
        reference_balance(&env, 0).await,
        "A after our own spend"
    );
    println!("[5] A after our spend: balance matches wallet2");

    // ---- 6. Reorg: pop 5 blocks, mine a different chain -----------------
    let height_before = a_state.cursor.unwrap().height;
    rpc(&env.daemon_http, "pop_blocks", json!({"nblocks": 5})).await;
    env.mine(7, &b_addr).await; // different miner → different blocks
    node.refresh_info().await.unwrap();
    let rep = sync(&mut a_state, &a_keys, node.daemon(), |_| {})
        .await
        .expect("sync after reorg");
    assert_eq!(rep.rolled_back, 5, "rolled back exactly the popped blocks");
    assert_eq!(a_state.cursor.unwrap().height, height_before + 2);
    env.open("a").await;
    a_state.import_key_images(&reference_key_images(&env, 1).await);
    assert_eq!(
        our_outputs(&a_state),
        reference_outputs(&env, 1).await,
        "A outputs after reorg"
    );
    println!("[6] reorg of 5 blocks handled; outputs match wallet2");

    // ---- 7. The node identity check refuses a wrong network -------------
    let ep = Endpoint {
        host: Host::Ip(std::net::IpAddr::from([127, 0, 0, 1])),
        port: env.daemon_port,
        transport: Transport::Direct,
        ownership: Ownership::Own,
    };
    let err = Node::connect(&NodeConfig::new(ep, Network::Stagenet), None)
        .await
        .unwrap_err();
    println!("[7] stagenet wallet vs regtest node refused: {err}");
    let _ = MoneroAddress::from_str(Network::Regtest.address_network(), &b_addr).unwrap();
}
