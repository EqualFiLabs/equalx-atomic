//! monero-rpc
//!
//! Minimal, blocking HTTP client for `monerod` public endpoints.
//! Endpoints used (public RPC only):
//! - GET  /get_height
//! - POST /json_rpc     (methods: "get_info", "get_block_header_by_height", "get_block_headers_range", "get_block", "get_fee_estimate")
//! - POST /get_transactions
//! - POST /sendrawtransaction
//! - POST /get_outs
//! - GET  /get_transaction_pool
//!
//! IMPORTANT: `submit_raw_tx` expects a raw tx blob produced by monero-oxide serialization.
//! We hex-encode the bytes and send them verbatim (no re-serialization).

use base64::{engine::general_purpose, Engine as _};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::time::Duration;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("rpc returned error: {0}")]
    Node(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("wallet rpc error (method {method}) code={code} message={message}")]
    Wallet {
        method: String,
        code: i64,
        message: String,
    },
    #[error("wallet rpc missing result for method {0}")]
    WalletResultMissing(String),
}

#[derive(Clone)]
pub struct MoneroRpc {
    base: Url,
    client: Client,
    auth_header: Option<HeaderValue>,
}

impl MoneroRpc {
    /// Create a new client. `base` like "http://127.0.0.1:18081".
    /// Optional basic auth via (user, pass). If None, no Authorization header is sent.
    pub fn new(base: &str, auth: Option<(String, String)>) -> Result<Self, RpcError> {
        let base = Url::parse(base)?;
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .default_headers(headers)
            .build()?;

        let auth_header = match auth {
            Some((user, pass)) => {
                let token = format!("{user}:{pass}");
                let enc = general_purpose::STANDARD.encode(token);
                let header_value = HeaderValue::from_str(&format!("Basic {}", enc))
                    .map_err(|e| RpcError::Decode(format!("auth header encode: {e}")))?;
                Some(header_value)
            }
            None => None,
        };

        Ok(Self {
            base,
            client,
            auth_header,
        })
    }

    fn auth_headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(a) = &self.auth_header {
            h.insert(AUTHORIZATION, a.clone());
        }
        h
    }

    fn json_rpc<P, R>(&self, method: &str, params: Option<&P>) -> Result<R, RpcError>
    where
        P: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        #[derive(Serialize)]
        struct Request<'a, T> {
            jsonrpc: &'a str,
            id: &'a str,
            method: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            params: Option<&'a T>,
        }

        #[derive(Deserialize)]
        struct Envelope<T> {
            result: Option<T>,
            error: Option<RpcErrorDetail>,
        }

        #[derive(Deserialize)]
        struct RpcErrorDetail {
            code: i64,
            message: String,
        }

        let url = self.base.join("/json_rpc")?;
        let request = Request {
            jsonrpc: "2.0",
            id: "0",
            method,
            params,
        };

        let resp = self
            .client
            .post(url)
            .headers(self.auth_headers())
            .json(&request)
            .send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!("{method} HTTP {}", resp.status())));
        }
        let envelope: Envelope<R> = resp.json()?;
        if let Some(err) = envelope.error {
            return Err(RpcError::Node(format!(
                "{method} error code={} message={}",
                err.code, err.message
            )));
        }
        envelope
            .result
            .ok_or_else(|| RpcError::Node(format!("{method} missing result")))
    }

    fn ensure_status_ok(status: &str, context: &str) -> Result<(), RpcError> {
        if status == "OK" {
            return Ok(());
        }
        Err(RpcError::Node(format!(
            "{context} returned status {status}"
        )))
    }

    /// GET /get_height
    pub fn get_height(&self) -> Result<u64, RpcError> {
        let url = self.base.join("/get_height")?;
        #[derive(Deserialize)]
        struct R {
            height: u64,
        }
        let resp = self.client.get(url).headers(self.auth_headers()).send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!("get_height HTTP {}", resp.status())));
        }
        let r: R = resp.json()?;
        Ok(r.height)
    }

    /// POST /is_key_image_spent
    pub fn is_key_image_spent(&self, key_images: &[Vec<u8>]) -> Result<Vec<u32>, RpcError> {
        #[derive(Serialize)]
        struct Req {
            key_images: Vec<String>,
        }

        let req = Req {
            key_images: key_images.iter().map(hex::encode).collect(),
        };

        let url = self.base.join("/is_key_image_spent")?;
        let resp = self
            .client
            .post(url)
            .headers(self.auth_headers())
            .json(&req)
            .send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!(
                "is_key_image_spent HTTP {}",
                resp.status()
            )));
        }
        let response: IsKeyImageSpentResponse = resp.json()?;
        Self::ensure_status_ok(&response.status, "is_key_image_spent")?;
        Ok(response.spent_status)
    }

    /// POST /json_rpc { method: "get_info" }
    pub fn get_info(&self) -> Result<GetInfo, RpcError> {
        self.json_rpc::<(), GetInfo>("get_info", None)
    }

    /// JSON-RPC `get_block_header_by_height`.
    pub fn get_block_header_by_height(
        &self,
        height: u64,
        fill_pow_hash: bool,
    ) -> Result<BlockHeaderResult, RpcError> {
        #[derive(Serialize)]
        struct Params {
            height: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            fill_pow_hash: Option<bool>,
        }
        let params = Params {
            height,
            fill_pow_hash: fill_pow_hash.then_some(true),
        };
        let response: BlockHeaderResult =
            self.json_rpc("get_block_header_by_height", Some(&params))?;
        Self::ensure_status_ok(&response.status, "get_block_header_by_height")?;
        Ok(response)
    }

    /// JSON-RPC `get_block_headers_range`.
    pub fn get_block_headers_range(
        &self,
        start_height: u64,
        end_height: u64,
        fill_pow_hash: bool,
    ) -> Result<BlockHeadersRangeResult, RpcError> {
        #[derive(Serialize)]
        struct Params {
            start_height: u64,
            end_height: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            fill_pow_hash: Option<bool>,
        }
        let params = Params {
            start_height,
            end_height,
            fill_pow_hash: fill_pow_hash.then_some(true),
        };
        let response: BlockHeadersRangeResult =
            self.json_rpc("get_block_headers_range", Some(&params))?;
        Self::ensure_status_ok(&response.status, "get_block_headers_range")?;
        Ok(response)
    }

    /// JSON-RPC `get_block` with arbitrary parameters.
    pub fn get_block(&self, params: &GetBlockParams) -> Result<BlockResult, RpcError> {
        let response: BlockResult = self.json_rpc("get_block", Some(params))?;
        Self::ensure_status_ok(&response.status, "get_block")?;
        Ok(response)
    }

    /// JSON-RPC `get_block` by hash.
    pub fn get_block_by_hash(
        &self,
        hash: &str,
        fill_pow_hash: bool,
    ) -> Result<BlockResult, RpcError> {
        let params = GetBlockParams {
            hash: Some(hash.to_string()),
            height: None,
            fill_pow_hash: fill_pow_hash.then_some(true),
        };
        self.get_block(&params)
    }

    /// JSON-RPC `get_block` by height.
    pub fn get_block_by_height(
        &self,
        height: u64,
        fill_pow_hash: bool,
    ) -> Result<BlockResult, RpcError> {
        let params = GetBlockParams {
            hash: None,
            height: Some(height),
            fill_pow_hash: fill_pow_hash.then_some(true),
        };
        self.get_block(&params)
    }

    /// POST `/get_transactions`.
    pub fn get_transactions(
        &self,
        request: &GetTransactionsRequest,
    ) -> Result<GetTransactionsResponse, RpcError> {
        let url = self.base.join("/get_transactions")?;
        let resp = self
            .client
            .post(url)
            .headers(self.auth_headers())
            .json(request)
            .send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!(
                "get_transactions HTTP {}",
                resp.status()
            )));
        }
        let response: GetTransactionsResponse = resp.json()?;
        Self::ensure_status_ok(&response.status, "get_transactions")?;
        Ok(response)
    }

    /// Convenience helper to fetch global output indices for a transaction.
    pub fn get_tx_global_output_indices(&self, tx_hash: &str) -> Result<Vec<u64>, RpcError> {
        let request = GetTransactionsRequest {
            txs_hashes: vec![tx_hash.to_string()],
            decode_as_json: Some(false),
            ..Default::default()
        };
        let response = self.get_transactions(&request)?;
        if let Some(entry) = response.txs.first() {
            return Ok(entry.output_indices.clone());
        }
        if !response.missed_tx.is_empty() {
            return Err(RpcError::Node(format!(
                "transaction {tx_hash} not found (missed)"
            )));
        }
        Err(RpcError::Node(format!("transaction {tx_hash} not found")))
    }

    /// POST `/get_outs`.
    ///
    /// Restricted daemons cap the number of outputs per request (currently ~100).
    /// Callers should batch large rings accordingly to avoid `Too many outs requested`.
    pub fn get_outs(&self, request: &GetOutsRequest) -> Result<GetOutsResponse, RpcError> {
        let url = self.base.join("/get_outs")?;
        let resp = self
            .client
            .post(url)
            .headers(self.auth_headers())
            .json(request)
            .send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!("get_outs HTTP {}", resp.status())));
        }
        let response: GetOutsResponse = resp.json()?;
        Self::ensure_status_ok(&response.status, "get_outs")?;
        Ok(response)
    }

    /// JSON-RPC `get_fee_estimate`.
    pub fn get_fee_estimate(
        &self,
        grace_blocks: Option<u64>,
    ) -> Result<FeeEstimateResult, RpcError> {
        let response: FeeEstimateResult = if let Some(grace) = grace_blocks {
            #[derive(Serialize)]
            struct Params {
                grace_blocks: u64,
            }
            let params = Params {
                grace_blocks: grace,
            };
            self.json_rpc("get_fee_estimate", Some(&params))?
        } else {
            self.json_rpc::<(), FeeEstimateResult>("get_fee_estimate", None)?
        };
        Self::ensure_status_ok(&response.status, "get_fee_estimate")?;
        Ok(response)
    }

    /// GET `/get_transaction_pool`.
    pub fn get_transaction_pool(&self) -> Result<GetTransactionPoolResponse, RpcError> {
        let url = self.base.join("/get_transaction_pool")?;
        let resp = self.client.get(url).headers(self.auth_headers()).send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!(
                "get_transaction_pool HTTP {}",
                resp.status()
            )));
        }
        let response: GetTransactionPoolResponse = resp.json()?;
        Self::ensure_status_ok(&response.status, "get_transaction_pool")?;
        Ok(response)
    }

    /// POST /get_transactions
    /// `tx_hash` must be hex string (lower/upper accepted by node).
    pub fn get_tx(&self, tx_hash: &str, decode_as_json: bool) -> Result<GetTxResult, RpcError> {
        let url = self.base.join("/get_transactions")?;
        #[derive(Serialize)]
        struct Req<'a> {
            txs_hashes: Vec<&'a str>,
            decode_as_json: bool,
        }
        let body = Req {
            txs_hashes: vec![tx_hash],
            decode_as_json,
        };
        let resp = self
            .client
            .post(url)
            .headers(self.auth_headers())
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!(
                "get_transactions HTTP {}",
                resp.status()
            )));
        }
        let raw: serde_json::Value = resp.json()?;
        Ok(GetTxResult { raw })
    }

    /// POST /sendrawtransaction
    /// Accepts raw tx bytes (from monero-oxide serialize), hex-encodes them, and submits.
    /// Returns tx hash and acceptance info. Use `do_not_relay=true` for a "dry-run" mempool check.
    pub fn submit_raw_tx(
        &self,
        tx_blob: &[u8],
        do_not_relay: bool,
        blink: bool,
    ) -> Result<SubmitResult, RpcError> {
        let url = self.base.join("/sendrawtransaction")?;
        let tx_as_hex = hex::encode(tx_blob);
        #[derive(Serialize)]
        struct Req<'a> {
            tx_as_hex: &'a str,
            do_not_relay: bool,
            blink: bool,
        }
        let body = Req {
            tx_as_hex: &tx_as_hex,
            do_not_relay,
            blink,
        };
        let resp = self
            .client
            .post(url)
            .headers(self.auth_headers())
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!(
                "sendrawtransaction HTTP {}",
                resp.status()
            )));
        }
        // Parse the entire JSON response so we can inspect unexpected fields.
        let val: Value = resp.json()?;
        #[derive(Deserialize)]
        struct SubmitResponse {
            status: Option<String>,
            not_relayed: Option<bool>,
            tx_hash: Option<String>,
            reason: Option<String>,
            credits: Option<u64>,
            error: Option<NodeErrorDetail>,
        }
        let parsed: SubmitResponse = serde_json::from_value(val.clone())
            .map_err(|e| RpcError::Decode(format!("sendrawtransaction decode: {e}")))?;
        let status = parsed.status.unwrap_or_else(|| "UNKNOWN".to_string());
        if status != "OK" && status != "Accepted" {
            return Err(RpcError::Node(format!(
                "submit failed status={status} reason={} raw={}",
                parsed
                    .reason
                    .clone()
                    .or_else(|| parsed.error.as_ref().and_then(|e| e.message.clone()))
                    .unwrap_or_default(),
                serde_json::to_string_pretty(&val).unwrap_or_else(|_| val.to_string())
            )));
        }
        Ok(SubmitResult {
            tx_hash: parsed.tx_hash.unwrap_or_default(),
            not_relayed: parsed.not_relayed.unwrap_or(false),
            status,
            reason: parsed.reason,
            credits: parsed.credits,
            error: parsed.error,
            raw: val,
        })
    }
}

/// Partial `get_info` result (fields we commonly use).
#[derive(Debug, Deserialize)]
pub struct GetInfo {
    pub height: Option<u64>,
    pub target_height: Option<u64>,
    pub mainnet: Option<bool>,
    pub nettype: Option<String>,
    pub difficulty: Option<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct BlockHeader {
    pub block_size: u64,
    pub block_weight: u64,
    pub cumulative_difficulty: u64,
    pub cumulative_difficulty_top64: u64,
    pub depth: u64,
    pub difficulty: u64,
    pub difficulty_top64: u64,
    pub hash: String,
    pub height: u64,
    pub long_term_weight: u64,
    pub major_version: u8,
    pub miner_tx_hash: String,
    pub minor_version: u8,
    pub nonce: u32,
    pub num_txes: u64,
    pub orphan_status: bool,
    pub pow_hash: String,
    pub prev_hash: String,
    pub reward: u64,
    pub timestamp: u64,
    pub wide_cumulative_difficulty: String,
    pub wide_difficulty: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct BlockHeaderResult {
    pub block_header: BlockHeader,
    pub credits: u64,
    pub status: String,
    pub top_hash: String,
    pub untrusted: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct BlockHeadersRangeResult {
    pub headers: Vec<BlockHeader>,
    pub credits: u64,
    pub status: String,
    pub top_hash: String,
    pub untrusted: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct BlockResult {
    pub blob: String,
    pub block_header: BlockHeader,
    pub credits: u64,
    pub json: String,
    pub miner_tx_hash: String,
    pub status: String,
    pub top_hash: String,
    pub tx_hashes: Vec<String>,
    pub untrusted: bool,
}

#[derive(Debug, Serialize, Clone, Default)]
#[serde(default)]
pub struct GetBlockParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill_pow_hash: Option<bool>,
}

#[derive(Debug, Serialize, Clone, Default)]
#[serde(default)]
pub struct GetTransactionsRequest {
    pub txs_hashes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs_hashes_blobs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_as_json: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prune: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct GetTransactionsResponse {
    pub credits: u64,
    pub status: String,
    pub top_hash: String,
    pub txs: Vec<DaemonTransaction>,
    pub txs_as_hex: Vec<String>,
    pub txs_as_json: Vec<String>,
    #[serde(rename = "missed_tx")]
    pub missed_tx: Vec<String>,
    pub untrusted: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct DaemonTransaction {
    pub as_hex: String,
    pub as_json: String,
    pub block_height: u64,
    pub confirmations: u64,
    pub double_spend_seen: bool,
    pub in_pool: bool,
    pub prunable_as_hex: String,
    pub prunable_hash: String,
    pub pruned_as_hex: String,
    pub relayed: bool,
    pub tx_hash: String,
    pub block_timestamp: u64,
    pub received_timestamp: u64,
    pub output_indices: Vec<u64>,
}

#[derive(Debug, Serialize, Clone)]
pub struct OutputRef {
    pub amount: u64,
    pub index: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct GetOutsRequest {
    pub outputs: Vec<OutputRef>,
    pub get_txid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct GetOutsResponse {
    pub credits: u64,
    pub outs: Vec<OutputEntry>,
    pub status: String,
    pub top_hash: String,
    pub untrusted: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct OutputEntry {
    pub height: u64,
    pub key: String,
    pub mask: String,
    pub txid: String,
    pub unlocked: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct IsKeyImageSpentResponse {
    pub credits: u64,
    pub spent_status: Vec<u32>,
    pub status: String,
    pub top_hash: String,
    pub untrusted: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct FeeEstimateResult {
    pub credits: u64,
    pub fee: u64,
    pub fees: Vec<u64>,
    pub quantization_mask: u64,
    pub status: String,
    pub top_hash: String,
    pub untrusted: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct GetTransactionPoolResponse {
    pub credits: u64,
    pub spent_key_images: Vec<SpentKeyImageInfo>,
    pub status: String,
    pub top_hash: String,
    pub transactions: Vec<TxPoolTxInfo>,
    pub untrusted: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct TxPoolTxInfo {
    pub id_hash: String,
    pub tx_json: String,
    pub blob_size: u64,
    pub weight: u64,
    pub fee: u64,
    pub max_used_block_id_hash: String,
    pub max_used_block_height: u64,
    pub kept_by_block: bool,
    pub last_failed_height: u64,
    pub last_failed_id_hash: String,
    pub receive_time: u64,
    pub relayed: bool,
    pub last_relayed_time: u64,
    pub do_not_relay: bool,
    pub double_spend_seen: bool,
    pub tx_blob: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct SpentKeyImageInfo {
    pub id_hash: String,
    pub txs_hashes: Vec<String>,
}

#[derive(Debug)]
pub struct SubmitResult {
    pub tx_hash: String,
    pub not_relayed: bool,
    pub status: String,
    pub reason: Option<String>,
    pub credits: Option<u64>,
    pub error: Option<NodeErrorDetail>,
    pub raw: Value,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeErrorDetail {
    pub code: Option<i64>,
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct GetTxResult {
    pub raw: Value,
}

#[derive(Clone)]
pub struct MoneroWalletRpc {
    base: Url,
    client: Client,
    auth_header: Option<HeaderValue>,
}

impl MoneroWalletRpc {
    /// Create a new wallet client. `base` like "http://127.0.0.1:18083".
    pub fn new(base: &str, auth: Option<(String, String)>) -> Result<Self, RpcError> {
        let base = Url::parse(base)?;
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .default_headers(headers)
            .build()?;

        let auth_header = match auth {
            Some((user, pass)) => {
                let token = format!("{user}:{pass}");
                let enc = general_purpose::STANDARD.encode(token);
                let header_value = HeaderValue::from_str(&format!("Basic {}", enc))
                    .map_err(|e| RpcError::Decode(format!("auth header encode: {e}")))?;
                Some(header_value)
            }
            None => None,
        };

        Ok(Self {
            base,
            client,
            auth_header,
        })
    }

    fn auth_headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(a) = &self.auth_header {
            h.insert(AUTHORIZATION, a.clone());
        }
        h
    }

    fn call<P, R>(&self, method: &str, params: &P) -> Result<R, RpcError>
    where
        P: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        #[derive(Serialize)]
        struct Request<'a, T> {
            jsonrpc: &'a str,
            id: &'a str,
            method: &'a str,
            params: &'a T,
        }

        #[derive(Deserialize)]
        struct Envelope {
            result: Option<Value>,
            error: Option<WalletError>,
        }

        #[derive(Deserialize)]
        struct WalletError {
            code: i64,
            message: String,
        }

        let url = self.base.join("/json_rpc")?;
        let req = Request {
            jsonrpc: "2.0",
            id: "0",
            method,
            params,
        };
        let resp = self
            .client
            .post(url)
            .headers(self.auth_headers())
            .json(&req)
            .send()?;
        if !resp.status().is_success() {
            return Err(RpcError::Node(format!("wallet rpc HTTP {}", resp.status())));
        }
        let envelope: Envelope = resp.json()?;
        if let Some(err) = envelope.error {
            return Err(RpcError::Wallet {
                method: method.to_string(),
                code: err.code,
                message: err.message,
            });
        }
        let result = envelope
            .result
            .ok_or_else(|| RpcError::WalletResultMissing(method.to_string()))?;
        serde_json::from_value::<R>(result)
            .map_err(|e| RpcError::Decode(format!("{method} decode: {e}")))
    }

    pub fn transfer(&self, params: &TransferParams) -> Result<TransferResult, RpcError> {
        self.call("transfer", params)
    }

    pub fn sweep_single(&self, params: &SweepSingleParams) -> Result<TransferResult, RpcError> {
        self.call("sweep_single", params)
    }

    pub fn describe_transfer(
        &self,
        params: &DescribeTransferParams,
    ) -> Result<DescribeTransferResult, RpcError> {
        self.call("describe_transfer", params)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransferDestination {
    pub amount: u64,
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TransferParams {
    pub destinations: Vec<TransferDestination>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subaddr_indices: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_tx_hex: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_tx_metadata: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub do_not_relay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_tx_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_tx_keys: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_multisig_txset: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_unsigned_txset: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wipeable_addresses: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SweepSingleParams {
    pub address: String,
    pub key_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_tx_hex: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_tx_metadata: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub do_not_relay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_tx_keys: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_multisig_txset: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_unsigned_txset: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DescribeTransferParams {
    pub tx_metadata: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TransferResult {
    pub amount: Option<u64>,
    pub fee: Option<u64>,
    pub tx_hash: Option<String>,
    pub tx_key: Option<String>,
    pub tx_blob: Option<String>,
    pub tx_metadata: Option<String>,
    pub unsigned_txset: Option<String>,
    pub multisig_txset: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DescribeTransferResult {
    pub desc: Vec<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde::Deserialize;
    use serde_json::json;

    #[test]
    fn deserialize_block_header_by_height_fixture() {
        #[derive(Deserialize)]
        struct Fixture {
            result: BlockHeaderResult,
        }
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../tests/fixtures/get_block_header_by_height.json"
        ))
        .unwrap();
        assert_eq!(fixture.result.status, "OK");
        assert_eq!(fixture.result.block_header.height, 1979012);
    }

    #[test]
    fn deserialize_block_fixture() {
        #[derive(Deserialize)]
        struct Fixture {
            result: BlockResult,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../tests/fixtures/get_block.json")).unwrap();
        assert_eq!(fixture.result.status, "OK");
        assert_eq!(
            fixture.result.block_header.hash,
            "f6968c438f41ea03a37f42346dbaa0822ee84eb45368fb4dd89f4eb2baa100ed"
        );
    }

    #[test]
    fn deserialize_block_headers_range_fixture() {
        #[derive(Deserialize)]
        struct Fixture {
            result: BlockHeadersRangeResult,
        }
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../tests/fixtures/get_block_headers_range.json"
        ))
        .unwrap();
        assert_eq!(fixture.result.status, "OK");
        assert_eq!(fixture.result.headers.len(), 3);
        assert_eq!(fixture.result.headers[0].height, 1979000);
    }

    #[test]
    fn deserialize_transactions_fixture() {
        let response: GetTransactionsResponse =
            serde_json::from_str(include_str!("../tests/fixtures/get_transactions.json")).unwrap();
        assert_eq!(response.status, "OK");
        assert_eq!(response.txs.len(), 1);
        assert_eq!(response.txs[0].output_indices, vec![0]);
    }

    #[test]
    fn deserialize_get_outs_fixture() {
        let response: GetOutsResponse =
            serde_json::from_str(include_str!("../tests/fixtures/get_outs.json")).unwrap();
        assert_eq!(response.status, "OK");
        assert_eq!(response.outs.len(), 1);
        assert!(response.outs[0].unlocked);
    }

    #[test]
    fn deserialize_fee_estimate_fixture() {
        #[derive(Deserialize)]
        struct Fixture {
            result: FeeEstimateResult,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../tests/fixtures/get_fee_estimate.json")).unwrap();
        assert_eq!(fixture.result.status, "OK");
        assert_eq!(fixture.result.fee, 28_000);
        assert_eq!(fixture.result.fees.len(), 4);
    }

    #[test]
    fn deserialize_transaction_pool_fixture() {
        let response: GetTransactionPoolResponse =
            serde_json::from_str(include_str!("../tests/fixtures/get_transaction_pool.json"))
                .unwrap();
        assert_eq!(response.status, "OK");
        assert!(response.transactions.is_empty());
        assert!(response.spent_key_images.is_empty());
    }

    #[test]
    fn get_transactions_http_error_becomes_rpc_error() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/get_transactions");
            then.status(500).body("boom");
        });

        let rpc = MoneroRpc::new(&server.base_url(), None).unwrap();
        let request = GetTransactionsRequest {
            txs_hashes: vec!["deadbeef".into()],
            ..Default::default()
        };
        let err = rpc.get_transactions(&request).unwrap_err();
        mock.assert();
        match err {
            RpcError::Node(msg) => assert!(msg.contains("HTTP 500")),
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn get_outs_non_ok_status_maps_to_rpc_error() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/get_outs");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    json!({
                        "credits": 0,
                        "outs": [],
                        "status": "BUSY",
                        "top_hash": "",
                        "untrusted": false
                    })
                    .to_string(),
                );
        });

        let rpc = MoneroRpc::new(&server.base_url(), None).unwrap();
        let request = GetOutsRequest {
            outputs: vec![OutputRef {
                amount: 0,
                index: 0,
            }],
            get_txid: true,
            client: Some("builder".into()),
        };
        let err = rpc.get_outs(&request).unwrap_err();
        mock.assert();
        match err {
            RpcError::Node(msg) => assert!(msg.contains("status BUSY")),
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn get_transactions_request_serialization_matches_daemon_payload() {
        let request = GetTransactionsRequest {
            txs_hashes: vec!["abc".into(), "def".into()],
            txs_hashes_blobs: Some(vec!["blob".into()]),
            decode_as_json: Some(true),
            prune: Some(false),
            split: Some(true),
            client: Some("test-suite".into()),
        };

        let serialized = serde_json::to_value(&request).unwrap();
        assert_eq!(
            serialized,
            json!({
                "txs_hashes": ["abc", "def"],
                "txs_hashes_blobs": ["blob"],
                "decode_as_json": true,
                "prune": false,
                "split": true,
                "client": "test-suite"
            })
        );
    }

    #[test]
    fn get_outs_request_serialization_matches_daemon_payload() {
        let request = GetOutsRequest {
            outputs: vec![
                OutputRef {
                    amount: 1_000_000_000_000,
                    index: 3,
                },
                OutputRef {
                    amount: 500_000_000_000,
                    index: 1,
                },
            ],
            get_txid: false,
            client: None,
        };
        let serialized = serde_json::to_value(&request).unwrap();
        assert_eq!(
            serialized,
            json!({
                "outputs": [
                    { "amount": 1_000_000_000_000u64, "index": 3u64 },
                    { "amount": 500_000_000_000u64, "index": 1u64 }
                ],
                "get_txid": false
            })
        );
    }
}
