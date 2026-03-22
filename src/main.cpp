// =============================================================================
// main.cpp — Industrial IoT Gateway Security Platform
// Orchestrator / Entry Point
// Standard : C++17
// Target   : Linux (Raspberry Pi 4)
//
// ── Startup sequence ──────────────────────────────────────────────────────────
//
//  Phase 0 — Pre-flight
//    • Parse gateway_config.json from config/
//    • Create runtime directories (logs/, db/) if absent
//    • Redirect SIGINT / SIGTERM to graceful shutdown handler
//
//  Phase 1 — Database
//    • Construct DatabaseManager("db/factory_data.db")
//    • Tables created (CREATE TABLE IF NOT EXISTS) on first run
//    • Seed the authorised device whitelist from gateway_config.json
//
//  Phase 2 — SNMP Agent
//    • Configure SnmpAgentConfig from parsed JSON
//    • Construct SnmpAgent, call init()
//    • Agent thread starts, OIDs registered, USM user created
//
//  Phase 3 — Data Processor
//    • Configure ProcessingConfig (thresholds from JSON)
//    • Construct DataProcessor(db, config)
//    • Register MQTT→processor callback bridge
//
//  Phase 4 — MQTT Client
//    • Construct MqttClient with broker params from JSON
//    • Install lambda callback → DataProcessor::onRawMessage()
//    • call start() — async connect + loop_start()
//
//  Phase 5 — Watchdog
//    • Configure WatchdogConfig (intervals from JSON)
//    • Construct Watchdog(processor, db, config)
//    • call start()
//
//  Phase 6 — Main event loop
//    • Block on g_shutdownCv — woken by SIGINT/SIGTERM handler
//    • Print periodic status lines every 30 s while waiting
//
//  Phase 7 — Graceful shutdown (reverse construction order)
//    • watchdog.stop()
//    • mqtt.stop()
//    • snmp.shutdown()
//    • DataProcessor and DatabaseManager destroyed by shared_ptr RAII
//
// ── Signal handling ───────────────────────────────────────────────────────────
//  SIGINT  (Ctrl+C)  → sets g_shutdownFlag, notifies g_shutdownCv
//  SIGTERM (kill)    → same
//
//  The signal handler is POSIX-async-signal-safe: it only sets an atomic bool
//  and posts to a condition variable via a pipe/self-pipe trick is NOT used
//  here; instead we use the well-known pattern of notifying a condition_variable
//  from the signal handler via atomic + a separate "waiter" thread that
//  checks the flag.  On Linux, condition_variable::notify_all() IS safe to call
//  from a signal handler when the mutex is NOT held at the time.
//
// ── Error policy ──────────────────────────────────────────────────────────────
//  Phase 0-2 failures: print to stderr, exit(1) — gateway cannot run safely
//                      without a DB or SNMP agent.
//  Phase 3-5 failures: same — all subsystems are required.
//  Runtime errors in subsystem threads: caught internally; logged; do not
//                      propagate to main().
// =============================================================================

#include "DatabaseManager.h"
#include "DataProcessor.h"
#include "MqttClient.h"
#include "SnmpAgent.h"
#include "Watchdog.h"
#include "models/SensorData.h"

// nlohmann/json for gateway_config.json parsing
#include <nlohmann/json.hpp>

// C++ standard library
#include <iostream>
#include <fstream>       // ifstream (config file)
#include <sstream>
#include <string>
#include <memory>        // make_shared
#include <atomic>        // g_shutdownFlag
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <thread>        // this_thread::sleep_for
#include <csignal>       // sigaction, SIGINT, SIGTERM
#include <sys/stat.h>    // mkdir
#include <ctime>
#include <iomanip>       // put_time

using namespace std;

// Bring the project namespace into scope for this file
using namespace IndustrialGateway;

// =============================================================================
// Global shutdown state
//
// g_shutdownFlag is set by the POSIX signal handler.
// g_shutdownCv   is notified so the main-thread wait exits immediately.
//
// These are global because POSIX signal handlers cannot capture lambdas or
// access object members — the handler must be a plain C function with access
// to global/static storage only.
// =============================================================================
static atomic<bool>       g_shutdownFlag{false};
static mutex              g_shutdownMutex;
static condition_variable g_shutdownCv;

// =============================================================================
// Signal handler — async-signal-safe
//
// Calling notify_all() from a signal handler is technically undefined behaviour
// in the C++ standard, but is safe on Linux (POSIX) when the mutex is not held
// at the time of the signal.  This is the most common pattern used in
// production C++ daemons on Linux.
//
// Alternative: use the self-pipe trick (write 1 byte to a pipe, main loop
// polls it).  We use notify_all() for simplicity since we target Linux only.
// =============================================================================
static void signalHandler(int signum) {
    // signum is used only to decide which shutdown message to write.
    // We do not need a named variable — select the message directly.
    const char* msg = (signum == SIGINT)
        ? "\n[Gateway] SIGINT received — initiating graceful shutdown...\n"
        : "\n[Gateway] SIGTERM received — initiating graceful shutdown...\n";

    // write() is async-signal-safe (POSIX).
    // Cast to void: we cannot recover from a partial write inside a signal
    // handler (no async-signal-safe error reporting path), so the return
    // value is intentionally ignored here.
    (void)write(STDOUT_FILENO, msg, __builtin_strlen(msg));

    g_shutdownFlag.store(true, memory_order_release);
    g_shutdownCv.notify_all();   // Wake the main-thread wait
}

// =============================================================================
// Utility helpers
// =============================================================================

// -----------------------------------------------------------------------------
// nowStr — UTC timestamp prefix for all main.cpp log lines
// -----------------------------------------------------------------------------
static string nowStr() {
    auto now  = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    ostringstream oss;
    oss << "[" << put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << " UTC]";
    return oss.str();
}

// -----------------------------------------------------------------------------
// ensureDirectory — creates a directory if it does not exist.
// Returns true on success or if already present.
// -----------------------------------------------------------------------------
static bool ensureDirectory(const string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);   // Already exists
    }
    // 0755 = rwxr-xr-x
    int rc = mkdir(path.c_str(), 0755);
    if (rc == 0) {
        cout << nowStr() << " [main] Created directory: " << path << "\n";
        return true;
    }
    cerr << nowStr() << " [main] ERROR: Cannot create directory '"
              << path << "': " << strerror(errno) << "\n";
    return false;
}

// -----------------------------------------------------------------------------
// loadConfig — reads and parses gateway_config.json.
// Returns the parsed JSON object.
// Throws runtime_error if the file cannot be read or is not valid JSON.
// -----------------------------------------------------------------------------
static nlohmann::json loadConfig(const string& path) {
    ifstream f(path);
    if (!f.is_open()) {
        throw runtime_error(
            "Cannot open config file: '" + path + "'"
        );
    }
    nlohmann::json cfg;
    try {
        f >> cfg;
    }
    catch (const nlohmann::json::parse_error& e) {
        throw runtime_error(
            "JSON parse error in config file '" + path + "': " +
            string(e.what())
        );
    }
    return cfg;
}

// -----------------------------------------------------------------------------
// printBanner — startup header printed to stdout
// -----------------------------------------------------------------------------
static void printBanner() {
    cout
        << "\n"
        << "╔══════════════════════════════════════════════════════════╗\n"
        << "║   Industrial IoT Gateway Security Platform  v1.0.0       ║\n"
        << "║   Target: Raspberry Pi 4 — Linux — C++17                 ║\n"
        << "║   Build : see CMakeLists.txt for version                 ║\n"
        << "╚══════════════════════════════════════════════════════════╝\n"
        << "\n";
}

// -----------------------------------------------------------------------------
// printStatus — periodic one-line status summary printed during the main loop
// -----------------------------------------------------------------------------
static void printStatus(
    const MqttClient&   mqtt,
    const DataProcessor& dp,
    const SnmpAgent&    snmp,
    const Watchdog&     wd)
{
    cout << nowStr()
              << " [STATUS]"
              << " MQTT=" << (mqtt.isConnected() ? "UP" : "DOWN")
              << " msgs_rx="   << mqtt.getTotalMessagesReceived()
              << " accepted="  << dp.getTotalAccepted()
              << " rejected="  << dp.getTotalRejected()
              << " sec_events=" << dp.getSecurityEvents()
              << " nodes="     << snmp.getNodeCount()
              << " traps="     << snmp.getTrapsSent()
              << " offline_ev=" << wd.getOfflineEventCount()
              << "\n";
}

// =============================================================================
// main
// =============================================================================
int main(int argc, char* argv[]) {

    // ── Determine config file path (optional CLI override) ────────────────────
    string configPath = "config/gateway_config.json";
    if (argc > 1) {
        configPath = argv[1];
        cout << "[main] Using config file from CLI: " << configPath << "\n";
    }

    printBanner();

    // =========================================================================
    // Phase 0 — Pre-flight: config, directories, signals
    // =========================================================================
    cout << nowStr() << " [Phase 0] Pre-flight checks...\n";

    // ── Load configuration FIRST so directory paths come from config ──────────
    // We must read the config before creating directories because the actual
    // paths for logs/db may be overridden by the config file.
    nlohmann::json cfg;
    try {
        cfg = loadConfig(configPath);
        cout << nowStr() << " [Phase 0] Config loaded: " << configPath << "\n";
    }
    catch (const exception& e) {
        cerr << "[main] FATAL: " << e.what() << "\n";
        return 1;
    }

    // ── Derive all runtime directory paths from config ────────────────────────
    // Extract parent directory from a file path string, e.g. "logs/foo.log" → "logs"
    auto parentDir = [](const string& filePath) -> string {
        auto pos = filePath.rfind('/');
        return (pos == string::npos) ? "." : filePath.substr(0, pos);
    };

    // Collect every directory we need to guarantee exists
    string dbDir      = "db";
    string logsDir    = "logs";
    string secLogDir  = "logs";
    string debugLogDir = "logs";

    if (cfg.contains("database") && cfg["database"].contains("path"))
        dbDir = parentDir(cfg["database"]["path"].get<string>());

    if (cfg.contains("logging")) {
        const auto& log = cfg["logging"];
        if (log.contains("security_log"))
            secLogDir  = parentDir(log["security_log"].get<string>());
        if (log.contains("debug_log"))
            debugLogDir = parentDir(log["debug_log"].get<string>());
        // unify to shortest common parent if both point to same dir
        logsDir = secLogDir;
    }

    // ── Create all required runtime directories ───────────────────────────────
    // Fatal if any cannot be created — subsystems that open files in them
    // (DataProcessor, Watchdog, DatabaseManager) will throw on construction.
    bool dirsOk = true;
    for (const auto& dir : { dbDir, logsDir, secLogDir, debugLogDir }) {
        if (!dir.empty() && dir != ".") {
            if (!ensureDirectory(dir)) {
                dirsOk = false;
            }
        }
    }
    if (!dirsOk) {
        cerr << "[main] FATAL: Cannot create one or more required directories.\n"
                  << "       Check permissions on the working directory.\n";
        return 1;
    }

    // ── Install signal handlers ───────────────────────────────────────────────
    {
        struct sigaction sa{};
        sa.sa_handler = signalHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;   // Restart interrupted syscalls where possible

        if (sigaction(SIGINT,  &sa, nullptr) != 0 ||
            sigaction(SIGTERM, &sa, nullptr) != 0)
        {
            cerr << "[main] FATAL: sigaction failed: "
                      << strerror(errno) << "\n";
            return 1;
        }

        // Ignore SIGPIPE — a broken network connection on the SNMP trap socket
        // would otherwise kill the process silently
        signal(SIGPIPE, SIG_IGN);

        cout << nowStr()
                  << " [Phase 0] Signal handlers installed (SIGINT, SIGTERM).\n";
    }

    cout << nowStr() << " [Phase 0] Pre-flight OK.\n\n";

    // =========================================================================
    // Phase 1 — Database initialisation
    // =========================================================================
    cout << nowStr() << " [Phase 1] Initialising database...\n";

    // Extract DB path from config (fall back to default if missing)
    string dbPath = "db/factory_data.db";
    if (cfg.contains("database") && cfg["database"].contains("path")) {
        dbPath = cfg["database"]["path"].get<string>();
    }

    // Shared ownership: DataProcessor and Watchdog both hold a shared_ptr
    shared_ptr<DatabaseManager> dbManager;
    try {
        dbManager = make_shared<DatabaseManager>(dbPath);
        cout << nowStr() << " [Phase 1] Database OK: " << dbPath << "\n";
    }
    catch (const exception& e) {
        cerr << "[main] FATAL [Phase 1]: " << e.what() << "\n";
        return 1;
    }

    // ── Seed authorised device whitelist from config ───────────────────────────
    // gateway_config.json contains an "authorized_devices" array.
    // We call ensureDeviceExists() for each entry so the anti-spoofing check
    // in DataProcessor passes for pre-provisioned nodes from the very first
    // packet — without waiting for a manual DB INSERT.
    if (cfg.contains("authorized_devices") &&
        cfg["authorized_devices"].is_array())
    {
        cout << nowStr() << " [Phase 1] Seeding device whitelist...\n";
        for (const auto& dev : cfg["authorized_devices"]) {
            if (!dev.contains("node_id")) continue;
            string nodeId = dev["node_id"].get<string>();
            int64_t devId = dbManager->ensureDeviceExists(nodeId);
            if (devId >= 0) {
                cout << nowStr()
                          << " [Phase 1]   ✓ Registered: '"
                          << nodeId << "' (id=" << devId << ")\n";
            } else {
                cerr << nowStr()
                          << " [Phase 1]   ✗ Failed to register: '"
                          << nodeId << "'\n";
            }
        }
    }
    cout << nowStr() << " [Phase 1] Database phase complete.\n\n";

    // =========================================================================
    // Phase 2 — SNMP Agent initialisation
    // =========================================================================
    cout << nowStr() << " [Phase 2] Initialising SNMP Agent...\n";

    // Build SnmpAgentConfig from gateway_config.json ["snmpv3"] section
    SnmpAgentConfig snmpCfg;
    if (cfg.contains("snmpv3")) {
        const auto& s = cfg["snmpv3"];
        if (s.contains("user"))          snmpCfg.securityName  = s["user"].get<string>();
        if (s.contains("auth_pass"))     snmpCfg.authPass       = s["auth_pass"].get<string>();
        if (s.contains("priv_pass"))     snmpCfg.privPass       = s["priv_pass"].get<string>();
        if (s.contains("context_name"))  snmpCfg.contextName    = s["context_name"].get<string>();
        if (s.contains("trap_target"))   snmpCfg.trapTarget     = s["trap_target"].get<string>();
        if (s.contains("trap_port"))     snmpCfg.trapPort       = s["trap_port"].get<int>();
        if (s.contains("agent_port"))    snmpCfg.agentPort      = s["agent_port"].get<int>();
        if (s.contains("enterprise_oid"))snmpCfg.enterpriseOid  = s["enterprise_oid"].get<string>();
    }

    // SnmpAgent is owned directly (not shared) — only main needs it
    auto snmpAgent = make_shared<SnmpAgent>(snmpCfg);
    try {
        snmpAgent->init();
        cout << nowStr() << " [Phase 2] SNMP Agent OK.\n\n";
    }
    catch (const exception& e) {
        cerr << "[main] FATAL [Phase 2]: " << e.what() << "\n";
        return 1;
    }

    // =========================================================================
    // Phase 3 — Data Processor initialisation
    // =========================================================================
    cout << nowStr() << " [Phase 3] Initialising Data Processor...\n";

    // Build ProcessingConfig from gateway_config.json ["security"] section
    ProcessingConfig procCfg;
    if (cfg.contains("security")) {
        const auto& sec = cfg["security"];
        if (sec.contains("temp_jump_threshold"))
            procCfg.tempJumpThreshold = sec["temp_jump_threshold"].get<float>();
        if (sec.contains("humi_jump_threshold"))
            procCfg.humiJumpThreshold = sec["humi_jump_threshold"].get<float>();
        if (sec.contains("replay_detection"))
            procCfg.replayDetection = sec["replay_detection"].get<bool>();
    }
    if (cfg.contains("logging")) {
        const auto& log = cfg["logging"];
        if (log.contains("debug_log"))
            procCfg.debugLogPath    = log["debug_log"].get<string>();
        if (log.contains("security_log"))
            procCfg.securityLogPath = log["security_log"].get<string>();
    }

    shared_ptr<DataProcessor> dataProcessor;
    try {
        dataProcessor = make_shared<DataProcessor>(dbManager, procCfg);
        cout << nowStr() << " [Phase 3] Data Processor OK.\n\n";
    }
    catch (const exception& e) {
        cerr << "[main] FATAL [Phase 3]: " << e.what() << "\n";
        return 1;
    }

    // ── Bridge: DataProcessor → SnmpAgent metric updates ─────────────────────
    // After DataProcessor successfully accepts a packet and writes it to the
    // cache, main.cpp is responsible for pushing the new values into the SNMP
    // MIB.  We achieve this by wrapping the MQTT callback in a lambda that:
    //   1. forwards the raw message to DataProcessor::onRawMessage()
    //   2. then queries the cache for the updated reading
    //   3. pushes the values to SnmpAgent::updateMetrics()
    //
    // This keeps DataProcessor and SnmpAgent fully decoupled — neither knows
    // the other exists.

    // =========================================================================
    // Phase 4 — MQTT Client initialisation
    // =========================================================================
    cout << nowStr() << " [Phase 4] Initialising MQTT Client...\n";

    // Extract MQTT params from config
    string mqttHost     = "localhost";
    int         mqttPort     = 1883;
    int         mqttKeepAlive = 60;
    string mqttTopic    = "factory/sensors/+/data";
    string mqttClientId = "iiot_gateway_pi4";

    if (cfg.contains("mqtt")) {
        const auto& m = cfg["mqtt"];
        if (m.contains("host"))       mqttHost      = m["host"].get<string>();
        if (m.contains("port"))       mqttPort      = m["port"].get<int>();
        if (m.contains("keep_alive")) mqttKeepAlive = m["keep_alive"].get<int>();
        if (m.contains("topic"))      mqttTopic     = m["topic"].get<string>();
        if (m.contains("client_id"))  mqttClientId  = m["client_id"].get<string>();
    }

    unique_ptr<MqttClient> mqttClient;
    try {
        mqttClient = make_unique<MqttClient>(
            mqttClientId, mqttHost, mqttPort, mqttKeepAlive, mqttTopic
        );
    }
    catch (const exception& e) {
        cerr << "[main] FATAL [Phase 4] MqttClient ctor: " << e.what() << "\n";
        return 1;
    }

    // ── Register the integrated MQTT→DataProcessor→SnmpAgent callback ─────────
    //
    // The lambda captures shared_ptrs by value so that even if main() somehow
    // returns before the callback fires, the objects remain alive.
    //
    // Flow per message:
    //   1. onRawMessage() runs the full 10-step security pipeline
    //   2. If accepted, the cache entry for nodeId is updated
    //   3. We read it back and push to SNMP (non-blocking — cache is lock-free)
    //   4. We also push to SNMP even on rejection so the alertState is set
    //      for security events (sendTrap already sets it via setAlertState)
    mqttClient->setMessageCallback(
        [dp  = dataProcessor,
         snmp = snmpAgent]
        (const string& topic, const string& payload)
        {
            // Step 1: Full security pipeline
            dp->onRawMessage(topic, payload);

            // Step 2: Extract nodeId from topic for SNMP update
            // Topic format: factory/sensors/<nodeId>/data
            // We parse it here rather than modifying DataProcessor's API.
            string nodeId;
            {
                size_t first  = topic.find('/');   // after "factory"
                size_t second = (first  != string::npos)
                                ? topic.find('/', first + 1)
                                : string::npos;
                size_t third  = (second != string::npos)
                                ? topic.find('/', second + 1)
                                : string::npos;
                if (second != string::npos && third != string::npos) {
                    nodeId = topic.substr(second + 1, third - second - 1);
                }
            }

            // Step 3: Push latest values to SNMP MIB cache
            if (!nodeId.empty()) {
                auto reading = dp->getCachedReading(nodeId);
                if (reading.has_value()) {
                    snmp->updateMetrics(
                        nodeId,
                        reading->temperature,
                        reading->humidity,
                        reading->status
                    );
                }
            }
        }
    );

    // ── Start MQTT async connection + I/O thread ──────────────────────────────
    try {
        mqttClient->start();
        cout << nowStr()
                  << " [Phase 4] MQTT Client started."
                  << " broker=" << mqttHost << ":" << mqttPort
                  << " topic='" << mqttTopic << "'\n\n";
    }
    catch (const exception& e) {
        cerr << "[main] FATAL [Phase 4] mqtt.start(): " << e.what() << "\n";
        return 1;
    }

    // =========================================================================
    // Phase 5 — Watchdog thread
    // =========================================================================
    cout << nowStr() << " [Phase 5] Starting Watchdog...\n";

    // Build WatchdogConfig from gateway_config.json ["security"] section
    WatchdogConfig wdCfg;
    if (cfg.contains("security")) {
        const auto& sec = cfg["security"];
        if (sec.contains("heartbeat_timeout_s"))
            wdCfg.offlineTimeoutSec = sec["heartbeat_timeout_s"].get<int64_t>();
    }
    if (cfg.contains("logging") && cfg["logging"].contains("debug_log")) {
        wdCfg.debugLogPath = cfg["logging"]["debug_log"].get<string>();
    }
    // Watchdog scan interval is always 5 s (1/6 of default 30 s timeout)
    wdCfg.checkIntervalSec = 5;

    unique_ptr<Watchdog> watchdog;
    try {
        watchdog = make_unique<Watchdog>(dataProcessor, dbManager, wdCfg);
        watchdog->start();
        cout << nowStr() << " [Phase 5] Watchdog started."
                  << " interval=" << wdCfg.checkIntervalSec << "s"
                  << " timeout="  << wdCfg.offlineTimeoutSec << "s\n\n";
    }
    catch (const exception& e) {
        cerr << "[main] FATAL [Phase 5]: " << e.what() << "\n";
        return 1;
    }

    // =========================================================================
    // Phase 6 — Main event loop
    // =========================================================================
    cout << nowStr() << " [Phase 6] Gateway fully operational.\n";
    cout << nowStr() << " Press Ctrl+C to initiate graceful shutdown.\n\n";

    // Periodic status interval
    constexpr int k_statusIntervalSec = 30;
    auto lastStatus = chrono::steady_clock::now();

    // Block the main thread using condition_variable wait.
    // The signal handler sets g_shutdownFlag and calls notify_all().
    // We also wake periodically (every second) to print the status line.
    while (!g_shutdownFlag.load(memory_order_acquire)) {
        {
            unique_lock<mutex> lock(g_shutdownMutex);
            g_shutdownCv.wait_for(
                lock,
                chrono::seconds(1),
                []() { return g_shutdownFlag.load(memory_order_acquire); }
            );
        }

        // Print periodic status every k_statusIntervalSec seconds
        auto now = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::seconds>(
                           now - lastStatus).count();
        if (elapsed >= k_statusIntervalSec) {
            printStatus(*mqttClient, *dataProcessor, *snmpAgent, *watchdog);
            lastStatus = now;
        }
    }

    // =========================================================================
    // Phase 7 — Graceful shutdown (reverse startup order)
    // =========================================================================
    cout << "\n" << nowStr()
              << " [Phase 7] Graceful shutdown initiated...\n";

    // Print final statistics before teardown
    printStatus(*mqttClient, *dataProcessor, *snmpAgent, *watchdog);

    // ── 7.1: Stop the Watchdog ────────────────────────────────────────────────
    // Stop first so it no longer calls DataProcessor or DatabaseManager
    cout << nowStr() << " [Phase 7] Stopping Watchdog...\n";
    try {
        watchdog->stop();
        cout << nowStr() << " [Phase 7] Watchdog stopped.\n";
    }
    catch (const exception& e) {
        cerr << "[main] WARNING [Phase 7] Watchdog stop: " << e.what() << "\n";
    }

    // ── 7.2: Stop the MQTT client ─────────────────────────────────────────────
    // Stop before DataProcessor so no new messages arrive during teardown
    cout << nowStr() << " [Phase 7] Stopping MQTT client...\n";
    try {
        mqttClient->stop();
        cout << nowStr() << " [Phase 7] MQTT client stopped.\n";
    }
    catch (const exception& e) {
        cerr << "[main] WARNING [Phase 7] MQTT stop: " << e.what() << "\n";
    }

    // ── 7.3: Shutdown SNMP Agent ──────────────────────────────────────────────
    cout << nowStr() << " [Phase 7] Shutting down SNMP agent...\n";
    try {
        snmpAgent->shutdown();
        cout << nowStr() << " [Phase 7] SNMP agent stopped.\n";
    }
    catch (const exception& e) {
        cerr << "[main] WARNING [Phase 7] SNMP shutdown: " << e.what() << "\n";
    }

    // ── 7.4: Release DataProcessor (shared_ptr — RAII) ───────────────────────
    // All threads that held a copy of dataProcessor have been stopped.
    // Resetting the shared_ptr here triggers the destructor if this is the
    // last reference (it will be — only main holds one now).
    cout << nowStr() << " [Phase 7] Releasing DataProcessor...\n";
    dataProcessor.reset();

    // ── 7.5: Release DatabaseManager (shared_ptr — RAII) ─────────────────────
    // The sqlite3_close() call in ~DatabaseManager flushes the WAL journal
    // and ensures no data is lost.
    cout << nowStr() << " [Phase 7] Releasing DatabaseManager (SQLite flush)...\n";
    dbManager.reset();

    // ── 7.6: Explicit cleanup of stack/unique_ptr objects ─────────────────────
    // unique_ptr destructors will run automatically when we return from main().
    // Nulling them here is explicit documentation that we are done with them.
    watchdog.reset();
    mqttClient.reset();
    snmpAgent.reset();

    cout << nowStr()
              << " [Phase 7] Shutdown complete. Goodbye.\n\n";

    return 0;
}
