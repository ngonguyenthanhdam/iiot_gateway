#!/usr/bin/env bash
# =============================================================================
# start_gateway.sh — Industrial IoT Gateway Launcher
# =============================================================================
# Starts the gateway binary from the project root, ensuring:
#   • The working directory is always the project root (so relative paths in
#     gateway_config.json such as "db/factory_data.db" and "logs/*.log" resolve
#     correctly regardless of where the script is invoked from).
#   • Mosquitto broker is running before the gateway starts.
#   • The build binary exists; if not, offers to build it.
#
# Usage:
#   ./scripts/start_gateway.sh                        # default config
#   ./scripts/start_gateway.sh config/my_config.json  # custom config path
# =============================================================================

set -euo pipefail

# Colour helpers
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[gateway]${NC} $*"; }
warn() { echo -e "${YELLOW}[gateway]${NC} $*"; }
err()  { echo -e "${RED}[gateway]${NC} $*" >&2; }

# ── Resolve project root (one level above scripts/) ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/build/iiot_gateway"
CONFIG="${1:-$PROJECT_ROOT/config/gateway_config.json}"

info "Project root : $PROJECT_ROOT"
info "Binary       : $BINARY"
info "Config       : $CONFIG"

# ── Check binary exists ───────────────────────────────────────────────────────
if [[ ! -f "$BINARY" ]]; then
    err "Binary not found: $BINARY"
    err "Build first:"
    err "  cmake -S $PROJECT_ROOT -B $PROJECT_ROOT/build -DCMAKE_BUILD_TYPE=Release"
    err "  cmake --build $PROJECT_ROOT/build -- -j\$(nproc)"
    exit 1
fi

# ── Check Mosquitto broker is running ─────────────────────────────────────────
if ! systemctl is-active --quiet mosquitto 2>/dev/null; then
    warn "Mosquitto broker is not running — attempting to start it..."
    sudo systemctl start mosquitto || {
        err "Cannot start Mosquitto. Start it manually: sudo systemctl start mosquitto"
        exit 1
    }
fi
info "Mosquitto broker: running"

# ── Ensure runtime directories exist ─────────────────────────────────────────
mkdir -p "$PROJECT_ROOT/logs" "$PROJECT_ROOT/db"

# ── Launch ────────────────────────────────────────────────────────────────────
info "Starting gateway... (Ctrl+C to stop)"
echo ""
cd "$PROJECT_ROOT"
exec "$BINARY" "$CONFIG"