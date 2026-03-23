#!/usr/bin/env bash
# =============================================================================
# setup_pi.sh — Industrial IoT Gateway: Raspberry Pi 4 Bootstrap Script
# =============================================================================
# Purpose:
#   Installs every system library, tool, and runtime dependency needed to
#   build and run the Industrial IoT Gateway Security Platform on a fresh
#   Raspberry Pi 4 running Raspberry Pi OS (Debian Bookworm/Bullseye, 64-bit).
#
# What this script does:
#   1. Preflight  — verify root, OS, architecture, internet connectivity
#   2. System     — apt update + upgrade, install build tools
#   3. Libraries  — all C/C++ development libraries the project links against
#   4. Mosquitto  — install broker + client libs; configure and enable service
#   5. Runtime    — create project directories, set permissions
#   6. Verify     — confirm every required library is discoverable by pkg-config
#   7. (Optional) — register the gateway as a systemd service
#
# Usage:
#   chmod +x scripts/setup_pi.sh
#   sudo ./scripts/setup_pi.sh                  # full install from project root
#   sudo ./scripts/setup_pi.sh --no-upgrade     # skip apt upgrade (faster)
#   sudo ./scripts/setup_pi.sh --service        # also install systemd service
#   sudo ./scripts/setup_pi.sh --skip-mosquitto # skip broker install/config
#
# After this script completes, build the project:
#   mkdir -p build && cd build
#   cmake .. -DCMAKE_BUILD_TYPE=Release
#   make -j$(nproc)
#   cd ..
#   ./build/iiot_gateway                        # run from project root
#
# Tested on:
#   Raspberry Pi OS 64-bit (Bookworm)  — Debian 12
#   Raspberry Pi OS 64-bit (Bullseye)  — Debian 11
# =============================================================================

set -euo pipefail   # Exit on error, undefined var, or pipeline failure
IFS=$'\n\t'         # Stricter word splitting

# =============================================================================
# Colour output helpers
# =============================================================================
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     NC='\033[0m'   # No Colour

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERROR]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; \
             echo -e "${BOLD}${CYAN}  $*${NC}"; \
             echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }

# =============================================================================
# CLI flags
# =============================================================================
DO_UPGRADE=true
INSTALL_SERVICE=false
SKIP_MOSQUITTO=false

for arg in "$@"; do
    case "$arg" in
        --no-upgrade)     DO_UPGRADE=false ;;
        --service)        INSTALL_SERVICE=true ;;
        --skip-mosquitto) SKIP_MOSQUITTO=true ;;
        --help|-h)
            echo "Usage: sudo $0 [--no-upgrade] [--service] [--skip-mosquitto]"
            exit 0 ;;
        *)
            err "Unknown option: $arg"
            exit 1 ;;
    esac
done

# =============================================================================
# 0. Preflight checks
# =============================================================================
section "Phase 0 — Preflight Checks"

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    err "Run: sudo $0"
    exit 1
fi
ok "Running as root."

# ── Architecture check ────────────────────────────────────────────────────────
ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" && "$ARCH" != "armv7l" && "$ARCH" != "x86_64" ]]; then
    warn "Unexpected architecture: $ARCH"
    warn "This script is designed for Raspberry Pi 4 (aarch64/armv7l)."
    warn "Continuing anyway — some packages may differ on your platform."
else
    ok "Architecture: $ARCH"
fi

# ── OS check ─────────────────────────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    info "OS: $PRETTY_NAME"
    # Warn if not Debian-based
    if [[ "${ID_LIKE:-$ID}" != *"debian"* && "$ID" != "debian" && "$ID" != "raspbian" ]]; then
        warn "This script uses apt — it may not work on non-Debian systems."
    fi
else
    warn "Cannot detect OS — /etc/os-release not found."
fi

# ── Internet connectivity check ───────────────────────────────────────────────
info "Checking internet connectivity..."
if ! ping -c 1 -W 3 8.8.8.8 &>/dev/null; then
    err "No internet connection detected."
    err "Please connect to the internet before running this script."
    exit 1
fi
ok "Internet connectivity OK."

# ── Determine project root (script lives in <project_root>/scripts/) ──────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
info "Project root: $PROJECT_ROOT"

# =============================================================================
# 1. System update & essential build tools
# =============================================================================
section "Phase 1 — System Update & Build Tools"

info "Updating package lists..."
apt-get update -qq

if $DO_UPGRADE; then
    info "Upgrading installed packages (use --no-upgrade to skip)..."
    apt-get upgrade -y -qq
    ok "System upgraded."
else
    warn "Skipping apt upgrade (--no-upgrade flag set)."
fi

# ── Core build toolchain ──────────────────────────────────────────────────────
info "Installing build toolchain..."
apt-get install -y -qq \
    build-essential \
    gcc \
    g++ \
    cmake \
    make \
    pkg-config \
    git \
    wget \
    curl \
    ca-certificates \
    lsb-release

ok "Build toolchain installed."

# ── Verify GCC/G++ version supports C++17 ─────────────────────────────────────
GCC_VER=$(g++ -dumpversion | cut -d. -f1)
if [[ "$GCC_VER" -lt 7 ]]; then
    err "g++ version $GCC_VER found — C++17 requires g++ 7 or later."
    err "On older Pi OS: sudo apt install g++-8 && sudo update-alternatives --set c++ /usr/bin/g++-8"
    exit 1
fi
ok "g++ version $GCC_VER supports C++17."

# ── Verify CMake version ──────────────────────────────────────────────────────
CMAKE_VER=$(cmake --version | head -1 | awk '{print $3}')
CMAKE_MAJ=$(echo "$CMAKE_VER" | cut -d. -f1)
CMAKE_MIN=$(echo "$CMAKE_VER" | cut -d. -f2)
if [[ "$CMAKE_MAJ" -lt 3 ]] || [[ "$CMAKE_MAJ" -eq 3 && "$CMAKE_MIN" -lt 16 ]]; then
    warn "CMake $CMAKE_VER found — project requires CMake 3.16+."
    warn "Installing cmake from Kitware apt repository..."
    # Kitware provides up-to-date CMake for Debian/Ubuntu/Raspbian
    wget -qO - https://apt.kitware.com/keys/kitware-archive-latest.asc \
        | gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] \
https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main" \
        > /etc/apt/sources.list.d/kitware.list
    apt-get update -qq
    apt-get install -y -qq cmake
    CMAKE_VER=$(cmake --version | head -1 | awk '{print $3}')
    ok "CMake upgraded to $CMAKE_VER"
else
    ok "CMake $CMAKE_VER OK."
fi

# =============================================================================
# 2. Core project libraries
# =============================================================================
section "Phase 2 — Core C++ Libraries"

# ── nlohmann/json (header-only, version 3.x) ─────────────────────────────────
info "Installing nlohmann/json..."
apt-get install -y -qq nlohmann-json3-dev
if dpkg -s nlohmann-json3-dev &>/dev/null; then
    ok "nlohmann-json3-dev installed."
else
    # Fallback: download the single-header directly
    warn "nlohmann-json3-dev not available via apt — downloading single header..."
    NLOHMANN_VER="3.11.3"
    NLOHMANN_URL="https://github.com/nlohmann/json/releases/download/v${NLOHMANN_VER}/json.hpp"
    mkdir -p /usr/local/include/nlohmann
    wget -q "$NLOHMANN_URL" -O /usr/local/include/nlohmann/json.hpp
    ok "nlohmann/json ${NLOHMANN_VER} installed to /usr/local/include/nlohmann/json.hpp"
fi

# ── SQLite3 ───────────────────────────────────────────────────────────────────
info "Installing SQLite3..."
apt-get install -y -qq \
    libsqlite3-dev \
    sqlite3
ok "SQLite3 installed: $(sqlite3 --version | cut -d' ' -f1)"

# ── net-snmp (SNMPv3 agent + tools) ───────────────────────────────────────────
info "Installing net-snmp..."
apt-get install -y -qq \
    libsnmp-dev \
    libssl-dev \
    snmp \
    snmpd \
    snmp-mibs-downloader
ok "net-snmp installed: $(net-snmp-config --version 2>/dev/null || echo 'version unavailable')"

# Ensure SNMP MIBs are downloadable (needed for OID resolution at runtime)
info "Downloading standard SNMP MIBs..."
download-mibs 2>/dev/null || warn "MIB download failed — non-critical."

# Enable loading of all MIBs in snmp.conf
SNMP_CONF="/etc/snmp/snmp.conf"
if [[ -f "$SNMP_CONF" ]]; then
    if ! grep -q "mibs +ALL" "$SNMP_CONF"; then
        echo "mibs +ALL" >> "$SNMP_CONF"
        ok "Added 'mibs +ALL' to $SNMP_CONF"
    fi
else
    mkdir -p /etc/snmp
    echo "mibs +ALL" > "$SNMP_CONF"
    ok "Created $SNMP_CONF with 'mibs +ALL'"
fi

# ── pthread (explicit linking for std::thread on Linux) ───────────────────────
# libc-dev provides pthread.h; the actual library is part of glibc
info "Verifying pthreads availability..."
apt-get install -y -qq libc6-dev
if ldconfig -p | grep -q "libpthread"; then
    ok "pthreads available."
else
    warn "libpthread not found in ldconfig — may be bundled with libc."
fi

# =============================================================================
# 3. MQTT — Mosquitto broker + C++ library
# =============================================================================
section "Phase 3 — MQTT (Mosquitto)"

if $SKIP_MOSQUITTO; then
    warn "Skipping Mosquitto install (--skip-mosquitto flag set)."
else
    info "Installing Mosquitto broker and C++ client library..."
    apt-get install -y -qq \
        mosquitto \
        mosquitto-clients \
        libmosquitto-dev \
        libmosquittopp-dev

    # ── Verify mosquittopp header and library are discoverable ────────────────
    if [[ ! -f /usr/include/mosquittopp.h ]]; then
        # Some distros put it in a subdirectory
        MOSQ_HEADER=$(find /usr/include /usr/local/include -name "mosquittopp.h" 2>/dev/null | head -1)
        if [[ -z "$MOSQ_HEADER" ]]; then
            err "mosquittopp.h not found after install — library may be broken."
            err "Try: sudo apt reinstall libmosquittopp-dev"
        else
            ok "mosquittopp.h found at: $MOSQ_HEADER"
        fi
    else
        ok "mosquittopp.h at /usr/include/mosquittopp.h"
    fi

    # ── Configure Mosquitto broker ─────────────────────────────────────────────
    MOSQ_CONF="/etc/mosquitto/conf.d/iiot_gateway.conf"
    info "Writing Mosquitto configuration to $MOSQ_CONF..."
    mkdir -p /etc/mosquitto/conf.d
    cat > "$MOSQ_CONF" <<'EOF'
# iiot_gateway.conf — Mosquitto configuration for Industrial IoT Gateway
# Listener: local only, no auth required (gateway runs on same host)
listener 1883 localhost

# Allow anonymous connections from localhost
allow_anonymous true

# Persistence (optional — stores retained messages across restarts)
persistence true
persistence_location /var/lib/mosquitto/

# Logging
log_dest file /var/log/mosquitto/mosquitto.log
log_type error
log_type warning
log_type notice
log_timestamp true

# Connection limits
max_connections 50
EOF
    ok "Mosquitto config written."

    # ── Enable and start Mosquitto service ────────────────────────────────────
    info "Enabling and starting Mosquitto service..."
    systemctl enable mosquitto
    systemctl restart mosquitto
    sleep 1

    if systemctl is-active --quiet mosquitto; then
        ok "Mosquitto broker is running on port 1883."
    else
        err "Mosquitto failed to start!"
        err "Check logs: sudo journalctl -u mosquitto -n 20"
        # Non-fatal — user may want to fix config manually
    fi

    # ── Smoke-test the broker ─────────────────────────────────────────────────
    info "Smoke-testing Mosquitto broker..."
    if mosquitto_sub -h localhost -t "test/ping" -C 1 -W 2 &>/dev/null & \
       sleep 0.2 && mosquitto_pub -h localhost -t "test/ping" -m "ok" &>/dev/null; then
        ok "Mosquitto broker is accepting connections."
    else
        warn "Broker smoke-test inconclusive — verify manually: mosquitto_pub -h localhost -t test -m hello"
    fi
fi

# =============================================================================
# 4. Project runtime directories
# =============================================================================
section "Phase 4 — Project Runtime Directories"

cd "$PROJECT_ROOT"
info "Working directory: $(pwd)"

for dir in build db logs scripts; do
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        ok "Created: $PROJECT_ROOT/$dir"
    else
        ok "Already exists: $PROJECT_ROOT/$dir"
    fi
done

# ── Set ownership to the invoking user (not root) ─────────────────────────────
# The gateway should run as a non-root user for security.
# SUDO_USER is set by sudo to the original user.
if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "$SUDO_USER:$SUDO_USER" \
        "$PROJECT_ROOT/build" \
        "$PROJECT_ROOT/db" \
        "$PROJECT_ROOT/logs"
    ok "Set ownership of build/, db/, logs/ → $SUDO_USER"
fi

# Touch the log files so they exist before first run (prevents
# confusion if a tool tries to tail them before the gateway starts)
touch "$PROJECT_ROOT/logs/system_debug.log"
touch "$PROJECT_ROOT/logs/security_alerts.log"
ok "Log files pre-created in logs/"

# =============================================================================
# 5. Verification — confirm every library is findable by the build system
# =============================================================================
section "Phase 5 — Library Verification"

VERIFY_FAILED=0

check_header() {
    local header="$1"
    local desc="$2"
    if [[ -f "/usr/include/$header" || -f "/usr/local/include/$header" ]]; then
        ok "$desc ($header)"
    else
        err "MISSING: $desc header not found: $header"
        VERIFY_FAILED=1
    fi
}

check_lib() {
    local lib="$1"
    local desc="$2"
    if ldconfig -p 2>/dev/null | grep -q "lib${lib}\.so" || \
       find /usr/lib /usr/local/lib -name "lib${lib}*.so*" 2>/dev/null | grep -q .; then
        ok "$desc (lib${lib})"
    else
        err "MISSING: $desc library not found: lib${lib}"
        VERIFY_FAILED=1
    fi
}

info "Checking required headers..."
check_header "mosquittopp.h"          "libmosquittopp C++ header"
check_header "mosquitto.h"            "libmosquitto C header"
check_header "sqlite3.h"              "SQLite3 C header"
check_header "net-snmp-config.h"      "net-snmp config header"
check_header "net-snmp-includes.h"    "net-snmp main header"
check_header "nlohmann/json.hpp"      "nlohmann/json header"

info "Checking required shared libraries..."
check_lib "mosquittopp"  "libmosquittopp"
check_lib "mosquitto"    "libmosquitto"
check_lib "sqlite3"      "libsqlite3"
check_lib "netsnmp"      "libnetsnmp"
check_lib "pthread"      "libpthread"

# ── pkg-config check (used by some CMake FindXxx modules) ────────────────────
info "Checking pkg-config entries..."
for pkg in sqlite3; do
    if pkg-config --exists "$pkg" 2>/dev/null; then
        ok "pkg-config: $pkg $(pkg-config --modversion $pkg)"
    else
        warn "pkg-config does not know '$pkg' — CMake find_library will be used instead."
    fi
done

if [[ $VERIFY_FAILED -ne 0 ]]; then
    err "One or more required libraries are missing."
    err "Re-run this script or install the missing packages manually."
    exit 1
fi

ok "All required libraries verified."

# =============================================================================
# 6. (Optional) Build the project immediately
# =============================================================================
section "Phase 6 — Build Project (optional)"

read -r -t 10 -p "$(echo -e "${CYAN}Build the gateway now? [y/N] (auto-skip in 10s): ${NC}")" BUILD_NOW \
    || BUILD_NOW="n"
echo ""

if [[ "${BUILD_NOW,,}" == "y" ]]; then
    info "Building project in $PROJECT_ROOT/build ..."
    cd "$PROJECT_ROOT"

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -Wno-dev
    cmake --build build -- -j"$(nproc)"

    if [[ -f "build/iiot_gateway" ]]; then
        ok "Build successful: $PROJECT_ROOT/build/iiot_gateway"
    else
        err "Build produced no binary — check CMake output above."
    fi
else
    info "Skipping build. To build later:"
    echo "    cd $PROJECT_ROOT"
    echo "    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release"
    echo "    cmake --build build -- -j\$(nproc)"
fi

# =============================================================================
# 7. (Optional) systemd service installation
# =============================================================================
if $INSTALL_SERVICE; then
    section "Phase 7 — systemd Service Installation"

    SERVICE_USER="${SUDO_USER:-pi}"
    SERVICE_FILE="/etc/systemd/system/iiot-gateway.service"

    info "Installing systemd service as user '$SERVICE_USER'..."

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Industrial IoT Gateway Security Platform
Documentation=https://github.com/your-org/iiot_gateway
After=network.target mosquitto.service
Requires=mosquitto.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${PROJECT_ROOT}
ExecStart=${PROJECT_ROOT}/build/iiot_gateway ${PROJECT_ROOT}/config/gateway_config.json
Restart=on-failure
RestartSec=5s

# Resource limits — appropriate for Raspberry Pi 4
MemoryMax=256M
CPUQuota=80%

# Logging — journald captures stdout/stderr
StandardOutput=journal
StandardError=journal
SyslogIdentifier=iiot-gateway

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable iiot-gateway

    ok "Service installed: $SERVICE_FILE"
    ok "Service enabled (will start on next boot)."
    info "To start now:    sudo systemctl start iiot-gateway"
    info "To check status: sudo systemctl status iiot-gateway"
    info "To view logs:    sudo journalctl -u iiot-gateway -f"
fi

# =============================================================================
# Summary
# =============================================================================
section "Setup Complete"

echo ""
echo -e "${GREEN}${BOLD}All dependencies installed successfully.${NC}"
echo ""
echo -e "${BOLD}Installed versions:${NC}"
g++ --version | head -1
cmake --version | head -1
sqlite3 --version
mosquitto -v 2>&1 | head -1 || mosquitto_sub --version 2>&1 | head -1 || true
net-snmp-config --version 2>/dev/null || echo "net-snmp: installed"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  1. cd $PROJECT_ROOT"
echo "  2. cmake -S . -B build -DCMAKE_BUILD_TYPE=Release"
echo "  3. cmake --build build -- -j\$(nproc)"
echo "  4. ./build/iiot_gateway                    # run from project root"
echo ""
if $INSTALL_SERVICE; then
    echo "  (or start the systemd service: sudo systemctl start iiot-gateway)"
    echo ""
fi
echo -e "${CYAN}SNMP testing (once gateway is running):${NC}"
echo "  snmpget -v3 -u admin_sec_gw -l authPriv \\"
echo "          -a SHA -A auth_password \\"
echo "          -x AES -X priv_password \\"
echo "          localhost .1.3.6.1.4.1.9999.1.1.1"
echo ""
echo -e "${CYAN}MQTT testing:${NC}"
echo "  mosquitto_pub -h localhost -t factory/sensors/ESP32_SEC_01/data \\"
echo "    -m '{\"node_id\":\"ESP32_SEC_01\",\"sensor_type\":\"ENV_MONITOR\",\"payload\":{\"temp\":25.5,\"humi\":45.2},\"status\":\"OPERATIONAL\",\"msg_id\":1,\"timestamp\":1715432000}'"
echo ""