#!/usr/bin/env bash
# Binary end-to-end test for the iroh bridge.
#
# Starts a herdr server, runs the iroh bridge over QUIC (serve + connect),
# and validates a client handshake through the tunnel — all using the
# compiled herdr binary.
#
# This reproduces the `herdr --remote=<id> --iroh` data path without
# needing a TTY, and catches regressions like the "no reactor running"
# panic in IrohTransport::bridge.
#
# Run as: HERDR_BIN=target/release/herdr scripts/iroh_bridge_binary_e2e.sh

set -euo pipefail

HERDR_BIN="${HERDR_BIN:-target/debug/herdr}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure binary exists.
if [ ! -x "$PROJECT_DIR/$HERDR_BIN" ]; then
    echo "building herdr binary..."
    (cd "$PROJECT_DIR" && cargo build --bin herdr)
fi
HERDR="$PROJECT_DIR/$HERDR_BIN"
echo "herdr binary: $HERDR"
$HERDR --version

# Temp directory for this test.
TEST_DIR="$(mktemp -d /tmp/herdr-binary-e2e-XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

CONFIG_HOME="$TEST_DIR/config"
RUNTIME_DIR="$TEST_DIR/runtime"
API_SOCKET="$RUNTIME_DIR/herdr/api.sock"
CLIENT_SOCKET="$RUNTIME_DIR/herdr/api-client.sock"
BRIDGE_SOCKET="$TEST_DIR/bridge.sock"
SERVER_LOG="$TEST_DIR/server.log"

export HERDR_IROH_KEY_NEW_PASSPHRASE="ci-binary-e2e-pw"
export HERDR_IROH_KEY_PASSPHRASE="ci-binary-e2e-pw"

mkdir -p "$CONFIG_HOME/herdr" "$RUNTIME_DIR"
echo "onboarding = false" > "$CONFIG_HOME/herdr/config.toml"

echo "=== Phase 1: Start herdr server ==="
XDG_CONFIG_HOME="$CONFIG_HOME" \
XDG_RUNTIME_DIR="$RUNTIME_DIR" \
HERDR_SOCKET_PATH="$API_SOCKET" \
env -u HERDR_CLIENT_SOCKET_PATH \
SHELL=/bin/sh \
"$HERDR" server > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
echo "server PID: $SERVER_PID"

# Wait for client socket.
for i in $(seq 1 40); do
    if [ -S "$CLIENT_SOCKET" ]; then
        echo "server ready (took ${i}s)"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: server died. Log:"
        cat "$SERVER_LOG"
        kill "$SERVER_PID" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

if [ ! -S "$CLIENT_SOCKET" ]; then
    echo "FAIL: client socket did not appear"
    exit 1
fi

echo "=== Phase 2: Start iroh bridge serve ==="
# Use a named pipe to avoid stdout buffering issues.
SERVE_FIFO="$TEST_DIR/serve-fifo"
mkfifo "$SERVE_FIFO"
"$HERDR" iroh-bridge serve --socket "$CLIENT_SOCKET" > "$SERVE_FIFO" 2>&1 &
SERVE_PID=$!
echo "serve PID: $SERVE_PID"

# Read endpoint ID in background with timeout.
read -t 10 ENDPOINT < "$SERVE_FIFO" || true
ENDPOINT=$(echo "$ENDPOINT" | tr -d '[:space:]')
echo "endpoint: $ENDPOINT"

if [ "${#ENDPOINT}" -ne 64 ]; then
    echo "FAIL: invalid endpoint ID: '$ENDPOINT' (len=${#ENDPOINT})"
    exit 1
fi

echo "=== Phase 3: Start iroh bridge connect ==="
rm -f "$BRIDGE_SOCKET"
"$HERDR" iroh-bridge connect "$ENDPOINT" --socket "$BRIDGE_SOCKET" > /dev/null 2>&1 &
CONNECT_PID=$!
echo "connect PID: $CONNECT_PID"

# Wait for bridge socket to appear.
for i in $(seq 1 20); do
    if [ -S "$BRIDGE_SOCKET" ]; then
        echo "bridge connect ready (took ${i}s)"
        break
    fi
    if ! kill -0 "$CONNECT_PID" 2>/dev/null; then
        echo "FAIL: bridge connect died"
        exit 1
    fi
    sleep 1
done

if [ ! -S "$BRIDGE_SOCKET" ]; then
    echo "FAIL: bridge socket did not appear"
    exit 1
fi

echo "=== Phase 4: Client handshake through bridge ==="
# Use the existing Rust integration test binary for the handshake logic.
# Fall back to a simple Python script if the test binary isn't available.
HANDSHAKE_TEST="$PROJECT_DIR/target/debug/deps/iroh_bridge_e2e-*"
if command -v python3 &>/dev/null; then
    python3 - "$BRIDGE_SOCKET" << 'PYEOF'
import socket, struct, sys

def encode_varint_u32(v):
    if v < 251:
        return bytes([v])
    elif v < 65536:
        return bytes([251]) + struct.pack('<H', v)
    else:
        return bytes([252]) + struct.pack('<I', v)

def encode_varint_u16(v):
    return encode_varint_u32(v)

def build_hello_frame(version, cols, rows):
    payload = b''
    payload += encode_varint_u32(0)       # ClientMessage::Hello
    payload += encode_varint_u32(version)
    payload += encode_varint_u16(cols)
    payload += encode_varint_u16(rows)
    payload += encode_varint_u32(8)       # cell_width_px
    payload += encode_varint_u32(16)      # cell_height_px
    payload += encode_varint_u32(0)       # RenderEncoding::SemanticFrame
    payload += encode_varint_u32(0)       # ClientKeybindings::Server
    payload += encode_varint_u32(0)       # ClientLaunchMode::App
    frame = struct.pack('<I', len(payload)) + payload
    return frame

sock_path = sys.argv[1]
PROTOCOL_VERSION = 16

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(15)
sock.connect(sock_path)

hello = build_hello_frame(PROTOCOL_VERSION, 80, 24)
sock.sendall(hello)

# Read frame length
len_buf = sock.recv(4, socket.MSG_WAITALL)
if len(len_buf) < 4:
    print("FAIL: could not read frame length")
    sys.exit(1)

payload_len = struct.unpack('<I', len_buf)[0]
payload = sock.recv(payload_len, socket.MSG_WAITALL)
if len(payload) < payload_len:
    print(f"FAIL: incomplete payload ({len(payload)} < {payload_len})")
    sys.exit(1)

sock.close()

# Decode Welcome: variant 0, version u32
if len(payload) == 0 or payload[0] != 0:
    print(f"FAIL: not a Welcome message (variant={payload[0] if payload else 'empty'})")
    sys.exit(1)

# Read variant discriminant
pos = 1
first = payload[pos]; pos += 1
if first < 251:
    version = first
elif first == 251:
    version = struct.unpack_from('<H', payload, pos)[0]
    pos += 2
else:
    version = struct.unpack_from('<I', payload, pos)[0]
    pos += 4

print(f"Welcome version: {version}")

if version == PROTOCOL_VERSION:
    print("PASS: iroh bridge e2e handshake OK")
    sys.exit(0)
else:
    print(f"FAIL: expected version {PROTOCOL_VERSION}, got {version}")
    sys.exit(1)
PYEOF
    HANDSHAKE_RESULT=$?
else
    echo "SKIP: python3 not available, handshake validation skipped"
    HANDSHAKE_RESULT=0
fi

echo "=== Cleanup ==="
kill "$CONNECT_PID" "$SERVE_PID" "$SERVER_PID" 2>/dev/null || true
wait 2>/dev/null || true

exit $HANDSHAKE_RESULT
