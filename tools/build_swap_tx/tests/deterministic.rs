use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use adaptor_clsag::{presig_region, tau};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use monero_generators::biased_hash_to_point;
use serde_json::json;
use tempfile::{tempdir, NamedTempFile};
use tx_builder::{ecdh, find_clsag_regions};

fn write_http_json(stream: &mut TcpStream, status: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn read_chunked_body(stream: &mut TcpStream) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let mut line = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => return body,
                Ok(_) => {
                    line.push(buf[0]);
                    if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
                        break;
                    }
                }
                Err(_) => return body,
            }
        }

        if line.len() < 2 {
            return body;
        }
        let size_str = String::from_utf8_lossy(&line[..line.len() - 2]);
        let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
        if size == 0 {
            let mut crlf = [0u8; 2];
            let _ = stream.read_exact(&mut crlf);
            break;
        }

        let mut chunk = vec![0u8; size];
        if stream.read_exact(&mut chunk).is_err() {
            break;
        }
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        let _ = stream.read_exact(&mut crlf);
    }
    body
}

fn parse_request(stream: &mut TcpStream) -> (String, String, HashMap<String, String>, Vec<u8>) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut header_bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                header_bytes.push(byte[0]);
                if header_bytes.len() >= 4 && header_bytes[header_bytes.len() - 4..] == *b"\r\n\r\n"
                {
                    break;
                }
            }
            Err(_) => break,
        }
        if header_bytes.len() > 8192 {
            break;
        }
    }
    let headers_str = String::from_utf8_lossy(&header_bytes);
    let mut lines = headers_str.lines();
    let request_line = lines.next().unwrap_or("GET / HTTP/1.1").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut body = Vec::new();
    if content_len > 0 {
        body.resize(content_len, 0);
        let _ = stream.read_exact(&mut body);
    } else if headers
        .get("transfer-encoding")
        .map(|v| v.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
    {
        body = read_chunked_body(stream);
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    (method, path, headers, body)
}

fn start_mock_daemon(
    tx_json: String,
    real_ring_key: [u8; 32],
    real_commitment: [u8; 32],
) -> (String, crossbeam_channel::Sender<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = crossbeam_channel::unbounded::<()>();

    // Shared JSON for get_transactions
    let tx_json_arc = Arc::new(tx_json);
    let served = Arc::new(Mutex::new(0usize));

    let tx_json_clone = Arc::clone(&tx_json_arc);
    let real_key_arc = Arc::new(real_ring_key);
    let real_commitment_arc = Arc::new(real_commitment);
    let served_clone = Arc::clone(&served);
    thread::spawn(move || {
        for stream in listener.incoming() {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            if let Ok(mut stream) = stream {
                let (_method, path, _headers, body) = parse_request(&mut stream);
                if path.starts_with("/get_height") {
                    write_http_json(
                        &mut stream,
                        "200 OK",
                        &json!({"height": 2_000_000}).to_string(),
                    );
                    continue;
                }
                if path.starts_with("/json_rpc") {
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    match method {
                        "get_fee_estimate" => {
                            let resp = json!({
                                "result": {
                                    "credits": 0,
                                    "fee": 200u64,
                                    "fees": [200u64,200u64,200u64,200u64],
                                    "quantization_mask": 0u64,
                                    "status": "OK",
                                    "top_hash": "",
                                    "untrusted": false
                                }
                            });
                            write_http_json(&mut stream, "200 OK", &resp.to_string());
                        }
                        "get_block" => {
                            // Always return one tx hash so max GI is found immediately
                            let resp = json!({
                                "result": {
                                    "blob": "",
                                    "block_header": {"hash":"", "height": 1u64, "block_size":0u64, "block_weight":0u64, "cumulative_difficulty":0u64, "cumulative_difficulty_top64":0u64, "depth":0u64, "difficulty":0u64, "difficulty_top64":0u64, "long_term_weight":0u64, "major_version":0u8, "miner_tx_hash":"", "minor_version":0u8, "nonce":0u32, "num_txes":0u64, "orphan_status":false, "pow_hash":"", "prev_hash":"", "reward":0u64, "timestamp":0u64, "wide_cumulative_difficulty":"0", "wide_difficulty":"0"},
                                    "credits": 0u64,
                                    "json": "{}",
                                    "miner_tx_hash": "",
                                    "status": "OK",
                                    "top_hash": "",
                                    "tx_hashes": ["cafebabe"],
                                    "untrusted": false
                                }
                            });
                            write_http_json(&mut stream, "200 OK", &resp.to_string());
                        }
                        _ => {
                            // Fallback OK
                            write_http_json(
                                &mut stream,
                                "200 OK",
                                &json!({"result": {"status":"OK"}}).to_string(),
                            );
                        }
                    }
                    continue;
                }
                if path.starts_with("/get_transactions") {
                    // Return one tx with our provided JSON and a non-empty output_indices
                    let as_json = tx_json_clone.as_str();
                    let resp = json!({
                        "credits": 0,
                        "status": "OK",
                        "top_hash": "",
                        "txs": [
                            {
                                "as_hex": "",
                                "as_json": as_json,
                                "block_height": 1,
                                "confirmations": 0,
                                "double_spend_seen": false,
                                "in_pool": false,
                                "prunable_as_hex": "",
                                "prunable_hash": "",
                                "pruned_as_hex": "",
                                "relayed": true,
                                "tx_hash": "deadbeef",
                                "block_timestamp": 0,
                                "received_timestamp": 0,
                                "output_indices": [10u64, 20u64, 30u64]
                            }
                        ],
                        "txs_as_hex": [],
                        "txs_as_json": [],
                        "missed_tx": [],
                        "untrusted": false
                    });
                    write_http_json(&mut stream, "200 OK", &resp.to_string());
                    *served_clone.lock().unwrap() += 1;
                    continue;
                }
                if path.starts_with("/get_outs") {
                    // Parse request to get number of outputs
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    let outs = v
                        .get("outputs")
                        .and_then(|o| o.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let mut outs_resp = Vec::with_capacity(outs.len());
                    for (i, entry) in outs.iter().enumerate() {
                        let gi = entry
                            .get("index")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(i as u64);
                        if gi == 100_000 {
                            outs_resp.push(json!({
                                "height": 0u64,
                                "key": hex::encode(real_key_arc.as_ref()),
                                "mask": hex::encode(real_commitment_arc.as_ref()),
                                "txid": "",
                                "unlocked": true
                            }));
                        } else {
                            let key_scalar = Scalar::from(gi.saturating_add(1));
                            let key_point = (ED25519_BASEPOINT_TABLE * &key_scalar).compress();
                            let commitment_scalar = Scalar::from(gi.saturating_add(2));
                            let commitment_point =
                                (ED25519_BASEPOINT_TABLE * &commitment_scalar).compress();
                            outs_resp.push(json!({
                                "height": 0u64,
                                "key": hex::encode(key_point.to_bytes()),
                                "mask": hex::encode(commitment_point.to_bytes()),
                                "txid": "",
                                "unlocked": true
                            }));
                        }
                    }
                    let resp = json!({
                        "credits": 0,
                        "outs": outs_resp,
                        "status": "OK",
                        "top_hash": "",
                        "untrusted": false
                    });
                    write_http_json(&mut stream, "200 OK", &resp.to_string());
                    continue;
                }
                // default
                write_http_json(&mut stream, "404 Not Found", "{}");
            }
        }
    });

    (format!("http://{}", addr), stop_tx)
}

fn hex32_to_arr(s: &str) -> [u8; 32] {
    let b = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}

#[test]
fn presig_deterministic_with_fixtures() {
    // Test parameters
    let view_key_hex = "0303030303030303030303030303030303030303030303030303030303030303";
    let spend_key_hex = "0505050505050505050505050505050505050505050505050505050505050505";

    // Build tx pubkey and tagged output for derive_key_offset success
    let view_scalar = Scalar::from_bytes_mod_order(hex32_to_arr(view_key_hex));
    let spend_scalar = Scalar::from_bytes_mod_order(hex32_to_arr(spend_key_hex));
    let spend_pub = (ED25519_BASEPOINT_TABLE * &spend_scalar)
        .compress()
        .to_bytes();

    let tx_scalar = Scalar::from_bytes_mod_order([7u8; 32]);
    let tx_pub = (ED25519_BASEPOINT_TABLE * &tx_scalar).compress().to_bytes();
    // derive shared scalar and tagged key for output index 0
    let ecdh_point = curve25519_dalek::edwards::CompressedEdwardsY(tx_pub)
        .decompress()
        .unwrap()
        * view_scalar;
    let (view_tag, derivations) = ecdh::derive_view_tag_and_shared(ecdh_point, 0);
    let shared_scalar = ecdh::shared_scalar(&derivations);
    let tagged = (ED25519_BASEPOINT_TABLE * &shared_scalar)
        + curve25519_dalek::edwards::CompressedEdwardsY(spend_pub)
            .decompress()
            .unwrap();
    let tagged_key_hex = hex::encode(tagged.compress().to_bytes());
    let view_tag_hex = format!("{:02x}", view_tag);

    // Transaction JSON (as string) matching daemon response schema used by the CLI
    // The CLI expects 'extra' as an array of integers and 'vout[0].target.tagged_key.{key,view_tag}'.
    let mut extra_bytes = vec![1u8];
    extra_bytes.extend_from_slice(&tx_pub);
    let extra_json = serde_json::Value::Array(
        extra_bytes
            .iter()
            .map(|b| serde_json::Value::from(*b as u64))
            .collect(),
    );
    let tx_as_json = json!({
        "extra": extra_json,
        "vout": [
            {"target": {"tagged_key": {"key": tagged_key_hex, "view_tag": view_tag_hex}}}
        ]
    })
    .to_string();

    const OWNED_AMOUNT: u64 = 3_000_000_000_000;
    let mask_scalar = ecdh::commitment_mask(&derivations);
    let mask_bytes = mask_scalar.to_bytes();
    let commitment_point = ecdh::output_commitment(mask_scalar, OWNED_AMOUNT);
    let commitment_bytes = commitment_point.to_bytes();
    let tagged_bytes = tagged.compress().to_bytes();
    let key_image_point = biased_hash_to_point(tagged_bytes) * (spend_scalar + shared_scalar);
    let key_image_bytes = key_image_point.compress().to_bytes();

    let owned_outputs_json = json!([
        {
            "txid": vec![170u8; 32],
            "out_index_in_tx": 0,
            "amount": OWNED_AMOUNT,
            "global_index": 100000,
            "mask": mask_bytes.to_vec(),
            "one_time_pubkey": tagged_bytes.to_vec(),
            "subaddr_account": 0,
            "subaddr_index": 0,
            "unlock_time": 0,
            "block_height": 246810,
            "key_image": key_image_bytes.to_vec()
        }
    ]);

    let mut owned_temp = NamedTempFile::new().expect("tmp owned outputs");
    serde_json::to_writer_pretty(owned_temp.as_file_mut(), &owned_outputs_json)
        .expect("write owned outputs fixture");
    owned_temp
        .as_file_mut()
        .sync_all()
        .expect("flush owned outputs");
    let owned_json_path = owned_temp.path().to_path_buf();

    // Start mock daemon with prepared tx JSON and real ring data
    let (daemon_url, stop_tx) = start_mock_daemon(tx_as_json, tagged_bytes, commitment_bytes);

    let out_dir = tempdir().expect("tmpdir");

    // Fixed settlement fields
    let chain_tag = "ACX-TEST";
    let position_key_hex =
        "bdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbd"; // 32 bytes (64 hex chars)
    let settle_digest_hex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"; // 32 bytes (64 hex chars)
    let swap_id_hex = "abababababababababababababababababababababababababababababababab"; // 32 bytes (64 hex chars)
    let message_hex = "00";

    // Invoke CLI binary directly
    let bin_path = env!("CARGO_BIN_EXE_build_swap_tx");
    let status = std::process::Command::new(bin_path)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../"))
        .args([
            "--daemon-url",
            &daemon_url,
            "--view-key-hex",
            view_key_hex,
            "--spend-key-hex",
            spend_key_hex,
            "--network",
            "mainnet",
            "--target-amount",
            "1000000000000",
            "--ring-size",
            "16",
            "--owned-json",
            owned_json_path.to_str().unwrap(),
            "--make-pre-sig",
            "--message-hex",
            message_hex,
            "--input-index",
            "0",
            "--chain-tag",
            chain_tag,
            "--position-key-hex",
            position_key_hex,
            "--settle-digest-hex",
            settle_digest_hex,
            "--swap-id-hex",
            swap_id_hex,
            "--deterministic",
            "--out-dir",
            out_dir.path().to_str().unwrap(),
        ])
        .status()
        .expect("spawn build_swap_tx");

    // Stop server
    let _ = stop_tx.send(());

    assert!(status.success(), "CLI exited with failure");

    // Assert outputs exist
    let pre_sig_tx = out_dir.path().join("pre_sig_tx.bin");
    let pre_sig_json = out_dir.path().join("pre_sig.json");
    let pre_sig_debug_json = out_dir.path().join("pre_sig.debug.json");
    assert!(pre_sig_tx.exists(), "pre_sig_tx.bin not found");
    assert!(pre_sig_json.exists(), "pre_sig.json not found");
    assert!(pre_sig_debug_json.exists(), "pre_sig.debug.json not found");

    // 1) Assert CLSAG regions exist
    let blob = std::fs::read(&pre_sig_tx).expect("read blob");
    let regions = find_clsag_regions(&blob).expect("find regions");
    assert!(!regions.is_empty(), "no CLSAG regions found in blob");

    // 2) Parse JSON and check fields
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pre_sig_json).unwrap()).unwrap();
    assert!(v.get("i_star").is_none(), "sanitized JSON leaked i_star");
    assert!(v.get("tau").is_none(), "sanitized JSON leaked tau");
    let pre = &v["pre"];
    let pre_j = v["pre_j"].as_u64().unwrap() as usize;
    assert!(pre_j < 16, "pre.j out of ring bounds");

    let pre_hash_hex = v["pre_hash"].as_str().unwrap();
    let settlement_ctx = &v["settlement_ctx"];
    let settlement_ctx_value = settlement_ctx.clone();
    let chain_tag_json = settlement_ctx["chain_tag"].as_str().unwrap();
    assert_eq!(chain_tag_json, chain_tag);
    let position_key_json = settlement_ctx["position_key"].as_str().unwrap();
    assert_eq!(position_key_json, position_key_hex.to_lowercase());
    let settle_digest_json = settlement_ctx["settle_digest"].as_str().unwrap();
    assert_eq!(settle_digest_json, settle_digest_hex.to_lowercase());

    // 3) Assert region bytes match serialize_presig_region
    let (_off, len) = regions[0];
    let s_tilde_hex = pre["s_tilde"].as_array().unwrap();
    let mut s_tilde = Vec::with_capacity(s_tilde_hex.len());
    for s in s_tilde_hex {
        let mut arr = [0u8; 32];
        let bytes = hex::decode(s.as_str().unwrap()).unwrap();
        arr.copy_from_slice(&bytes);
        s_tilde.push(arr);
    }
    let mut c1 = [0u8; 32];
    c1.copy_from_slice(&hex::decode(pre["c1_tilde"].as_str().unwrap()).unwrap());
    let mut d = [0u8; 32];
    d.copy_from_slice(&hex::decode(pre["d_tilde"].as_str().unwrap()).unwrap());
    let mut pseudo = [0u8; 32];
    pseudo.copy_from_slice(&hex::decode(pre["pseudo_out"].as_str().unwrap()).unwrap());

    let pre_sig = adaptor_clsag::PreSig {
        c1_tilde: c1,
        s_tilde,
        d_tilde: d,
        pseudo_out: pseudo,
        j: pre_j,
        ctx: adaptor_clsag::SettlementCtx {
            chain_tag: chain_tag.to_string(),
            position_key: hex32_to_arr(position_key_hex),
            settle_digest: hex32_to_arr(settle_digest_hex),
        },
        pre_hash: hex32_to_arr(pre_hash_hex),
    };

    let expected_region = presig_region::serialize_presig_region(&pre_sig, len).unwrap();
    let actual_region = tx_builder::read_clsag_subrange(&blob, 0, 0, len).expect("read region");
    assert_eq!(
        expected_region, actual_region,
        "presig region bytes mismatch"
    );

    // 4) Assert tau derived is consistent (debug artifact only)
    let debug_v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pre_sig_debug_json).unwrap()).unwrap();
    let tau_hex = debug_v["tau"].as_str().unwrap();
    let i_star = debug_v["i_star"].as_u64().unwrap() as usize;
    assert!(i_star < 16, "witness index out of ring bounds");
    assert_eq!(
        debug_v["settlement_ctx"], settlement_ctx_value,
        "debug settlement_ctx must mirror sanitized output"
    );

    let mut tau_bytes = [0u8; 32];
    tau_bytes.copy_from_slice(&hex::decode(tau_hex).unwrap());
    let derived_tau = tau::derive_tau(
        &pre_sig.ctx.settle_digest,
        &hex32_to_arr(swap_id_hex),
        &pre_sig.pre_hash,
        pre_sig.j as u32,
    );
    assert_eq!(tau_bytes, derived_tau, "tau derivation mismatch");
}
