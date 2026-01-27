#!/usr/bin/env bash
set -euo pipefail

LOG="SWAP-LOG.log"
echo "=== Local testing run started $(date -u '+%Y-%m-%dT%H:%M:%SZ') ===" >> "$LOG"
exec > >(tee -a "$LOG")
exec 2> >(tee -a "$LOG" >&2)
set -x

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

export MONERO_RPC="${MONERO_RPC:-http://127.0.0.1:58081}"
export ANVIL_RPC="${ANVIL_RPC:-http://127.0.0.1:8545}"
export MAKER_KEY="${MAKER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
export TAKER_KEY="${TAKER_KEY:-0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d}"
export DEST_SUBADDR="${DEST_SUBADDR:-75dhVBBKvsDJKbYBwdFfnkXD4Lqseq15aRRwtpLEGm2cKtjgLJo8xUfGpgJvWocN1vaDHxfheVvRkGZMRJTSotUmNTzPe5a}"
export DEST_AMOUNT_PICONERO="${DEST_AMOUNT_PICONERO:-1000000000000}"
export MONERO_FEE_BUFFER_PICONERO="${MONERO_FEE_BUFFER_PICONERO:-10000000000}"
TARGET_AMOUNT_PICONERO="$(python3 - <<'PY'
import os
dest = int(os.environ["DEST_AMOUNT_PICONERO"])
buf = int(os.environ.get("MONERO_FEE_BUFFER_PICONERO", "0"))
print(dest + buf)
PY
)"
export TARGET_AMOUNT_PICONERO
export RING_SIZE=${RING_SIZE:-16}
export SIM_CHAIN_ID=${SIM_CHAIN_ID:-}
export POSITION_KEY_HEX="${POSITION_KEY_HEX:-}"

export MAKER_ADDR="$(cast wallet address --private-key "$MAKER_KEY")"
export TAKER_ADDR="$(cast wallet address --private-key "$TAKER_KEY")"
CHAIN_ID="$(cast chain-id --rpc-url "$ANVIL_RPC")"
export CHAIN_ID
if [ -z "${SIM_CHAIN_ID:-}" ]; then
  export SIM_CHAIN_ID="$CHAIN_ID"
fi

printenv | sort

cast chain-id --rpc-url "$ANVIL_RPC"
curl -sS -X POST "$MONERO_RPC"/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_block_count"}'

forge build >/dev/null

deploy_contract() {
  local artifact="$1"
  shift || true
  local output addr
  if [ "$#" -gt 0 ]; then
    output="$(forge create "$artifact" --rpc-url "$ANVIL_RPC" --private-key "$MAKER_KEY" --broadcast --constructor-args "$@")"
  else
    output="$(forge create "$artifact" --rpc-url "$ANVIL_RPC" --private-key "$MAKER_KEY" --broadcast)"
  fi
  echo "$output" >&2
  addr="$(printf '%s\n' "$output" | sed -n 's/Deployed to: //p' | tail -n 1)"
  if [ -z "$addr" ]; then
    echo "Failed to deploy $artifact" >&2
    exit 1
  fi
  echo "$addr"
}

cast_send() {
  local key="$1"
  shift
  cast send --rpc-url "$ANVIL_RPC" --private-key "$key" "$@"
}

cast_send_json() {
  local key="$1"
  shift
  local output
  if ! output="$(cast send --json --rpc-url "$ANVIL_RPC" --private-key "$key" "$@" 2>&1)"; then
    echo "$output" >&2
    return 1
  fi
  if ! printf '%s' "$output" | python3 -c 'import json,sys;json.load(sys.stdin)' >/dev/null 2>&1
  then
    echo "Expected JSON output from cast send, got:" >&2
    echo "$output" >&2
    return 1
  fi
  printf '%s' "$output"
}

broadcast_address() {
  local run_latest="$1"
  local contract_name="$2"
  python3 - "$run_latest" "$contract_name" <<'PY'
import json
import sys

path = sys.argv[1]
name = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
for tx in data.get("transactions", []):
    if tx.get("contractName") == name and tx.get("contractAddress"):
        print(tx["contractAddress"])
        raise SystemExit(0)
raise SystemExit(1)
PY
}

get_pool_underlying() {
  local pool_id="$1"
  cast call "$DIAMOND" "getPoolUnderlying(uint256)(address)" "$pool_id" --rpc-url "$ANVIL_RPC"
}

approve_token() {
  local token="$1"
  local owner_key="$2"
  local spender="$3"
  local amount="$4"
  if [ "$token" = "0x0000000000000000000000000000000000000000" ]; then
    return 0
  fi
  cast_send "$owner_key" "$token" "approve(address,uint256)" "$spender" "$amount"
}

DIAMOND="${DIAMOND:-}"
MAILBOX="${MAILBOX:-}"
POSITION_NFT="${POSITION_NFT:-}"

if [ -z "$DIAMOND" ]; then
  export OWNER="$MAKER_ADDR"
  export TIMELOCK="$MAKER_ADDR"
  export TREASURY="$MAKER_ADDR"
  export PRIVATE_KEY="$MAKER_KEY"
  forge script script/DeployDiamond.s.sol:DeployDiamondScript --rpc-url "$ANVIL_RPC" --broadcast --skip-simulation
fi

RUN_LATEST="$REPO_ROOT/broadcast/DeployDiamond.s.sol/$CHAIN_ID/run-latest.json"
if [ -z "$DIAMOND" ]; then
  DIAMOND="$(broadcast_address "$RUN_LATEST" Diamond)"
fi
if [ -z "$MAILBOX" ]; then
  MAILBOX="$(broadcast_address "$RUN_LATEST" Mailbox)"
fi
if [ -z "$POSITION_NFT" ]; then
  POSITION_NFT="$(broadcast_address "$RUN_LATEST" PositionNFT)"
fi

if [ -z "$DIAMOND" ] || [ -z "$MAILBOX" ] || [ -z "$POSITION_NFT" ]; then
  echo "Failed to resolve diamond deployment addresses." >&2
  exit 1
fi

log_addr() {
  printf '%s: %s\n' "$1" "$2"
}

log_addr "Diamond" "$DIAMOND"
log_addr "Mailbox" "$MAILBOX"
log_addr "PositionNFT" "$POSITION_NFT"

KEY_REGISTRY_ADDR="${KEY_REGISTRY_ADDR:-$(deploy_contract src/EqualX/EncPubRegistry.sol:EncPubRegistry)}"
log_addr "EncPubRegistry" "$KEY_REGISTRY_ADDR"

BASE_POOL_ID="${BASE_POOL_ID:-4}"
QUOTE_POOL_ID="${QUOTE_POOL_ID:-5}"

if [ "$BASE_POOL_ID" -gt "$QUOTE_POOL_ID" ]; then
  DESK_POOL_A="$QUOTE_POOL_ID"
  DESK_POOL_B="$BASE_POOL_ID"
  BASE_IS_A=false
else
  DESK_POOL_A="$BASE_POOL_ID"
  DESK_POOL_B="$QUOTE_POOL_ID"
  BASE_IS_A=true
fi

TOKEN_A="$(get_pool_underlying "$DESK_POOL_A")"
TOKEN_B="$(get_pool_underlying "$DESK_POOL_B")"
if [ "$BASE_IS_A" = "true" ]; then
  BASE_TOKEN="$TOKEN_A"
  QUOTE_TOKEN="$TOKEN_B"
else
  BASE_TOKEN="$TOKEN_B"
  QUOTE_TOKEN="$TOKEN_A"
fi
export BASE_TOKEN QUOTE_TOKEN

log_addr "TokenA" "$TOKEN_A"
log_addr "TokenB" "$TOKEN_B"
log_addr "BaseToken" "$BASE_TOKEN"
log_addr "QuoteToken" "$QUOTE_TOKEN"

MAX_UINT="0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

BASE_DEPOSIT_AMOUNT="${BASE_DEPOSIT_AMOUNT:-600000000000000000000}"
QUOTE_DEPOSIT_AMOUNT="${QUOTE_DEPOSIT_AMOUNT:-600000000}"
RESERVE_AMOUNT="${RESERVE_AMOUNT:-50000000000000000000}"

approve_token "$BASE_TOKEN" "$MAKER_KEY" "$DIAMOND" "$MAX_UINT"
approve_token "$QUOTE_TOKEN" "$MAKER_KEY" "$DIAMOND" "$MAX_UINT"

START_SUPPLY="$(cast call "$POSITION_NFT" "totalSupply()(uint256)" --rpc-url "$ANVIL_RPC")"
POSITION_ID=$((START_SUPPLY + 1))

cast_send "$MAKER_KEY" "$DIAMOND" "mintPositionWithDeposit(uint256,uint256)" "$BASE_POOL_ID" "$BASE_DEPOSIT_AMOUNT"
cast_send "$MAKER_KEY" "$DIAMOND" "depositToPosition(uint256,uint256,uint256)" "$POSITION_ID" "$QUOTE_POOL_ID" "$QUOTE_DEPOSIT_AMOUNT"

POSITION_KEY_HEX="$(cast call "$POSITION_NFT" "getPositionKey(uint256)(bytes32)" "$POSITION_ID" --rpc-url "$ANVIL_RPC")"
POSITION_KEY_HEX="${POSITION_KEY_HEX#0x}"
export POSITION_KEY_HEX

DESK_ID="$(cast keccak "$(cast abi-encode "f(bytes32,uint256,uint256)" "0x$POSITION_KEY_HEX" "$DESK_POOL_A" "$DESK_POOL_B")")"

cast_send "$MAKER_KEY" "$DIAMOND" "registerDesk(uint256,uint256,uint256,bool)" "$POSITION_ID" "$BASE_POOL_ID" "$QUOTE_POOL_ID" "$BASE_IS_A"
log_addr "DeskId" "$DESK_ID"

TAKER_PUB_UNCOMP="$(cast wallet public-key --private-key "$TAKER_KEY" | sed 's/^0x//')"
TAKER_PUBKEY="$(TAKER_PUB_UNCOMP="$TAKER_PUB_UNCOMP" python3 - <<'PY'
import os
pub = os.environ['TAKER_PUB_UNCOMP']
if not pub.startswith('04'):
    pub = '04' + pub
x = pub[2:66]
y = pub[66:]
prefix = '03' if (int(y[-2:], 16) & 1) else '02'
print('0x' + prefix + x)
PY
)"
MAKER_PUB_UNCOMP="$(cast wallet public-key --private-key "$MAKER_KEY" | sed 's/^0x//')"
MAKER_PUBKEY="$(MAKER_PUB_UNCOMP="$MAKER_PUB_UNCOMP" python3 - <<'PY'
import os
pub = os.environ['MAKER_PUB_UNCOMP']
if not pub.startswith('04'):
    pub = '04' + pub
x = pub[2:66]
y = pub[66:]
prefix = '03' if (int(y[-2:], 16) & 1) else '02'
print('0x' + prefix + x)
PY
)"

CARGO_MANIFEST="$REPO_ROOT/atomic/Cargo.toml"

cargo run --manifest-path "$CARGO_MANIFEST" -p eswp-cli -- atomic-desk register-key \
  --registry "$KEY_REGISTRY_ADDR" \
  --pubkey "$MAKER_PUBKEY" \
  --rpc-url "$ANVIL_RPC" \
  --private-key "$MAKER_KEY"
cargo run --manifest-path "$CARGO_MANIFEST" -p eswp-cli -- atomic-desk register-key \
  --registry "$KEY_REGISTRY_ADDR" \
  --pubkey "$TAKER_PUBKEY" \
  --rpc-url "$ANVIL_RPC" \
  --private-key "$TAKER_KEY"
cast call "$KEY_REGISTRY_ADDR" "getEncPub(address)(bytes)" "$MAKER_ADDR" --rpc-url "$ANVIL_RPC"
cast call "$KEY_REGISTRY_ADDR" "getEncPub(address)(bytes)" "$TAKER_ADDR" --rpc-url "$ANVIL_RPC"

export RESERVATION_COUNTER=1
SETTLEMENT_PAYLOAD_HEX="$(python3 - <<'PY'
import os

def strip0x(val: str) -> str:
    return val[2:] if val.startswith("0x") else val

def hex32(val: int) -> str:
    return f"{val:064x}"

counter = int(os.environ["RESERVATION_COUNTER"])
position_key = strip0x(os.environ["POSITION_KEY_HEX"])
quote = strip0x(os.environ["QUOTE_TOKEN"])
base = strip0x(os.environ["BASE_TOKEN"])
taker = strip0x(os.environ["TAKER_ADDR"])
desk = strip0x(os.environ["MAKER_ADDR"])
chain_id = int(os.environ["CHAIN_ID"])

payload = (
    hex32(counter)
    + position_key.rjust(64, "0")
    + quote.rjust(40, "0")
    + base.rjust(40, "0")
    + taker.rjust(40, "0")
    + desk.rjust(40, "0")
    + hex32(chain_id)
)
print(payload)
PY
)"
SETTLEMENT_DIGEST="$(cast keccak "0x$SETTLEMENT_PAYLOAD_HEX")"

NOW=$(date +%s)
EXPIRY=$((NOW + 3600))

RESERVE_TX_JSON="$(cast_send_json "$MAKER_KEY" "$DIAMOND" \
  "reserveAtomicSwap(bytes32,address,address,uint256,bytes32,uint64)" \
  "$DESK_ID" "$TAKER_ADDR" "$BASE_TOKEN" "$RESERVE_AMOUNT" "$SETTLEMENT_DIGEST" "$EXPIRY" \
)"
RESERVE_TX_HASH="$(RESERVE_TX_JSON="$RESERVE_TX_JSON" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["RESERVE_TX_JSON"])
print(data["transactionHash"])
PY
)"

RESERVATION_ID="$(RESERVE_TX_HASH="$RESERVE_TX_HASH" python3 - <<'PY'
import json
import os
import subprocess

tx = os.environ["RESERVE_TX_HASH"]
rpc = os.environ["ANVIL_RPC"]
receipt = json.loads(
    subprocess.check_output(["cast", "receipt", "--json", tx, "--rpc-url", rpc])
)
sig = subprocess.check_output(
    ["cast", "keccak", "AtomicDeskReservationCreated(bytes32,bytes32,address,address,uint256,bytes32,uint64,uint64)"]
).decode().strip().lower()
for log in receipt.get("logs", []):
    topics = [t.lower() for t in log.get("topics", [])]
    if topics and topics[0] == sig:
        print("0x" + topics[1][2:].rjust(64, "0"))
        raise SystemExit(0)
raise SystemExit(1)
PY
)"

SWAP_ID="$RESERVATION_ID"
log_addr "ReservationId" "$RESERVATION_ID"

RAW_TAU="0x$(openssl rand -hex 32)"
TAU_SECRET="0x$(RAW_TAU="$RAW_TAU" python3 - <<'PY'
import os
L = 2**252 + 27742317777372353535851937790883648493
raw = int(os.environ['RAW_TAU'][2:], 16)
print(format(raw % L, '064x'))
PY
)"
HASHLOCK="$(cast keccak "$TAU_SECRET")"
M_DIGEST="0x$(openssl rand -hex 32)"

cast_send "$MAKER_KEY" "$DIAMOND" "setHashlock(bytes32,bytes32)" "$RESERVATION_ID" "$HASHLOCK"
cast_send "$TAKER_KEY" "$MAILBOX" "publishContext(bytes32,bytes)" "$RESERVATION_ID" 0x01

export MONERO_VIEW_KEY_HEX="${MONERO_VIEW_KEY_HEX:-00b02da20af616632f7962a45960fa82ce2b24a2d00153fe362459451802aa06}"
export MONERO_SPEND_KEY_HEX="${MONERO_SPEND_KEY_HEX:-14dffe59f41706b0a7a528700a8ebc9c1838eb8a4cdcdbde78b484257e16a001}"
SCAN_START_PRIMARY=${SCAN_START_PRIMARY:-2000000}
SCAN_END_PRIMARY=${SCAN_END_PRIMARY:-2000681}
SCAN_START_FALLBACK=${SCAN_START_FALLBACK:-1999000}
SCAN_END_FALLBACK=${SCAN_END_FALLBACK:-2001465}
MONERO_TX_ID_OVERRIDE="${MONERO_TX_ID_OVERRIDE:-}"
MONERO_TX_ID=""

build_presig() {
  cargo run --manifest-path "$CARGO_MANIFEST" -p build_swap_tx --bin build_swap_tx -- \
    --daemon-url "$MONERO_RPC" \
    --view-key-hex "$MONERO_VIEW_KEY_HEX" \
    --spend-key-hex "$MONERO_SPEND_KEY_HEX" \
    --network stagenet \
    --subaddr 0:0 \
    --dest "${DEST_SUBADDR}:${DEST_AMOUNT_PICONERO}" \
    --target-amount "$TARGET_AMOUNT_PICONERO" \
    --ring-size "$RING_SIZE" \
    --scan-start "$1" \
    --scan-end "$2" \
    --make-pre-sig \
    --deterministic \
    --message-hex "${M_DIGEST#0x}" \
    --chain-tag "$SIM_CHAIN_ID" \
    --position-key-hex "$POSITION_KEY_HEX" \
    --settle-digest-hex "${SETTLEMENT_DIGEST#0x}" \
    --swap-id-hex "${SWAP_ID#0x}" \
    --adaptor-secret-hex "${TAU_SECRET#0x}" \
    --out-dir out \
    --verbose
}

if ! build_presig "$SCAN_START_PRIMARY" "$SCAN_END_PRIMARY"; then
  build_presig "$SCAN_START_FALLBACK" "$SCAN_END_FALLBACK"
fi

COMMON_CONTEXT_ARGS=(
  --chain-id "$SIM_CHAIN_ID"
  --escrow "$DIAMOND"
  --swap-id "$SWAP_ID"
  --settle-digest "$SETTLEMENT_DIGEST"
  --m-digest "$M_DIGEST"
  --maker "$MAKER_ADDR"
  --taker "$TAKER_ADDR"
)

PRESIG_ENVELOPE_FILE="$(mktemp)"
cargo run --manifest-path "$CARGO_MANIFEST" -p eswp-cli -- atomic-desk publish-presig \
  "${COMMON_CONTEXT_ARGS[@]}" \
  --taker-pubkey "$TAKER_PUBKEY" \
  --presig-file out/pre_sig.json \
  --mailbox "$MAILBOX" \
  --rpc-url "$ANVIL_RPC" \
  --private-key "$MAKER_KEY" \
  --emit-parts \
  --no-broadcast \
  --envelope-out "$PRESIG_ENVELOPE_FILE"
PRESIG_ENVELOPE_HEX="$(tr -d '\n' < "$PRESIG_ENVELOPE_FILE")"
cast_send "$MAKER_KEY" "$MAILBOX" "publishPreSig(bytes32,bytes)" "$RESERVATION_ID" "$PRESIG_ENVELOPE_HEX"
rm -f "$PRESIG_ENVELOPE_FILE"

FINALIZE_LOG=""

extract_monero_tx_id() {
  local source="$1"
  local raw=""
  if command -v rg >/dev/null 2>&1; then
    raw="$(rg -o "Final transaction hash: (0x)?[0-9a-fA-F]{64}" "$source" | tail -n 1 | awk '{print $NF}')"
    if [ -z "$raw" ]; then
      raw="$(rg -o "0x[0-9a-fA-F]{64}" "$source" | tail -n 1 || true)"
    fi
  else
    raw="$(grep -Eo 'Final transaction hash: (0x)?[0-9a-fA-F]{64}' "$source" | tail -n 1 | awk '{print $NF}')"
    if [ -z "$raw" ]; then
      raw="$(grep -Eo '0x[0-9a-fA-F]{64}' "$source" | tail -n 1 || true)"
    fi
  fi
  if [ -n "$raw" ]; then
    if [[ "$raw" != 0x* ]]; then
      raw="0x$raw"
    fi
    MONERO_TX_ID="$raw"
  else
    MONERO_TX_ID=""
  fi
}

finalize_broadcast() {
  local start="$1"
  local end="$2"
  local log_file
  log_file="$(mktemp)"
  if cargo run --manifest-path "$CARGO_MANIFEST" -p build_swap_tx --bin build_swap_tx -- \
    --daemon-url "$MONERO_RPC" \
    --view-key-hex "$MONERO_VIEW_KEY_HEX" \
    --spend-key-hex "$MONERO_SPEND_KEY_HEX" \
    --network stagenet \
    --subaddr 0:0 \
    --dest "${DEST_SUBADDR}:${DEST_AMOUNT_PICONERO}" \
    --target-amount "$TARGET_AMOUNT_PICONERO" \
    --ring-size "$RING_SIZE" \
    --scan-start "$start" \
    --scan-end "$end" \
    --make-pre-sig \
    --finalize \
    --broadcast \
    --deterministic \
    --message-hex "${M_DIGEST#0x}" \
    --chain-tag "$SIM_CHAIN_ID" \
    --position-key-hex "$POSITION_KEY_HEX" \
    --settle-digest-hex "${SETTLEMENT_DIGEST#0x}" \
    --swap-id-hex "${SWAP_ID#0x}" \
    --adaptor-secret-hex "${TAU_SECRET#0x}" \
    --out-dir out \
    --verbose | tee "$log_file"; then
    FINALIZE_LOG="$log_file"
    extract_monero_tx_id "$log_file"
    return 0
  fi
  return 1
}

if ! finalize_broadcast "$SCAN_START_PRIMARY" "$SCAN_END_PRIMARY"; then
  finalize_broadcast "$SCAN_START_FALLBACK" "$SCAN_END_FALLBACK"
fi
if [ -z "$MONERO_TX_ID" ]; then
  if [ -n "$MONERO_TX_ID_OVERRIDE" ]; then
    MONERO_TX_ID="$MONERO_TX_ID_OVERRIDE"
    echo "Using override MONERO_TX_ID=$MONERO_TX_ID"
  else
    echo "Failed to extract Monero tx id from finalize logs" >&2
    [ -n "$FINALIZE_LOG" ] && echo "Inspect log: $FINALIZE_LOG" >&2
    exit 1
  fi
fi

TXPROOF_ENVELOPE_FILE="$(mktemp)"
cargo run --manifest-path "$CARGO_MANIFEST" -p eswp-cli -- atomic-desk tx-proof \
  "${COMMON_CONTEXT_ARGS[@]}" \
  --monero-tx-id "$MONERO_TX_ID" \
  --desk-pubkey "$MAKER_PUBKEY" \
  --taker-secret "$TAKER_KEY" \
  --mailbox "$MAILBOX" \
  --rpc-url "$ANVIL_RPC" \
  --private-key "$TAKER_KEY" \
  --dry-run \
  --envelope-out "$TXPROOF_ENVELOPE_FILE"

TXPROOF_ENVELOPE_HEX="$(tr -d '\n' < "$TXPROOF_ENVELOPE_FILE")"
cast_send "$TAKER_KEY" "$MAILBOX" "publishFinalSig(bytes32,bytes)" "$RESERVATION_ID" "$TXPROOF_ENVELOPE_HEX"
rm -f "$TXPROOF_ENVELOPE_FILE"

DECRYPT_LOG="$(mktemp)"
cargo run --manifest-path "$CARGO_MANIFEST" -p eswp-cli -- atomic-desk decrypt-tx-proof \
  "${COMMON_CONTEXT_ARGS[@]}" \
  --desk-secret "$MAKER_KEY" \
  --mailbox "$MAILBOX" \
  --rpc-url "$ANVIL_RPC" | tee "$DECRYPT_LOG"
DECRYPTED_MONERO_TX_ID="$(awk -F '=' '/moneroTxId=/{print $2}' "$DECRYPT_LOG" | tail -n 1 | tr -d '[:space:]')"
if [ -z "$DECRYPTED_MONERO_TX_ID" ] || [ "${DECRYPTED_MONERO_TX_ID,,}" != "${MONERO_TX_ID,,}" ]; then
  echo "Decrypted Monero tx id mismatch (got $DECRYPTED_MONERO_TX_ID expected $MONERO_TX_ID)" >&2
  exit 1
fi

cast_send "$MAKER_KEY" "$DIAMOND" "settle(bytes32,bytes32)" "$RESERVATION_ID" "$TAU_SECRET"

echo "=== Local testing run completed $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
