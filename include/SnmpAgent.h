// =============================================================================
// SnmpAgent.h  —  SNMPv3 Agent & Trap Sender
// Industrial IoT Gateway Security Platform
// Standard : C++17
//
// ── Responsibilities ──────────────────────────────────────────────────────────
//  1. Initialise the net-snmp agent library and register OIDs under the
//     enterprise branch  .1.3.6.1.4.1.9999
//
//  2. Register a scalar MIB subtree exposing per-node sensor metrics:
//       .1.3.6.1.4.1.9999.1.<nodeIndex>.1  — device_status  (Integer32)
//       .1.3.6.1.4.1.9999.1.<nodeIndex>.2  — temperature    (Gauge32, ×10)
//       .1.3.6.1.4.1.9999.1.<nodeIndex>.3  — humidity       (Gauge32, ×10)
//       .1.3.6.1.4.1.9999.1.<nodeIndex>.4  — alert_state    (Integer32)
//
//  3. Run the net-snmp agent event loop on a dedicated background thread so
//     that SNMP GET requests are served without blocking the MQTT pipeline.
//
//  4. Provide updateMetrics(nodeId, temp, humi, status) so DataProcessor and
//     the Watchdog can push new values into the MIB cache at any time.
//
//  5. Provide sendTrap(eventType, nodeId, detail) to proactively push
//     SNMPv3 INFORM/TRAP packets to the NMS (e.g. Zabbix) whenever a
//     security incident is detected.
//
// ── OID layout ────────────────────────────────────────────────────────────────
//  Enterprise root   :  .1.3.6.1.4.1.9999
//  Sensor data branch:  .1.3.6.1.4.1.9999.1
//  Trap branch       :  .1.3.6.1.4.1.9999.2
//
//  Per-node scalars  :  .1.3.6.1.4.1.9999.1.<nodeIndex>.<column>
//    column 1 = device_status   Integer32  (0=OK, 1=WARN, 2=CRIT, 4=OFFLINE)
//    column 2 = temperature     Gauge32    (°C × 10, e.g. 25.5°C → 255)
//    column 3 = humidity        Gauge32    (%RH × 10, e.g. 45.2% → 452)
//    column 4 = alert_state     Integer32  (0=clear, 1=alert active)
//
//  Trap OIDs         :  .1.3.6.1.4.1.9999.2.<trapType>
//    trapType 1 = device_offline
//    trapType 2 = anomaly_detected
//    trapType 3 = unauthorized_device
//    trapType 4 = replay_attack
//
// ── SNMPv3 security profile ───────────────────────────────────────────────────
//  Security name  : admin_sec_gw
//  Security level : authPriv  (authentication + encryption both required)
//  Auth protocol  : SHA-1     (HMAC-SHA-96)
//  Priv protocol  : AES-128   (CFB mode)
//  Context name   : factory_context
//
// ── Threading model ───────────────────────────────────────────────────────────
//  • init() starts a background std::thread that runs agent_check_and_process()
//    in a tight loop, serving incoming GET/GETNEXT/GETBULK requests.
//  • updateMetrics() is called from the MQTT loop thread; it acquires
//    m_metricsMutex before touching the MIB value cache.
//  • sendTrap() is called from DataProcessor / Watchdog threads; it builds
//    and dispatches the trap PDU under m_trapMutex.
//  • shutdown() signals the agent thread to exit and joins it.
//
// ── Error policy ──────────────────────────────────────────────────────────────
//  • init() throws std::runtime_error if the net-snmp library cannot be
//    initialised or the USM user cannot be created.
//  • updateMetrics() / sendTrap() never throw; failures are logged to stderr.
// =============================================================================

#ifndef IIOT_GATEWAY_SNMP_AGENT_H
#define IIOT_GATEWAY_SNMP_AGENT_H

// ---------------------------------------------------------------------------
// net-snmp isolation
//
// ALL three net-snmp headers are included ONLY in SnmpAgent.cpp, in this
// mandatory order:
//   #include <net-snmp/net-snmp-config.h>
//   #include <net-snmp/net-snmp-includes.h>
//   #include <net-snmp/agent/net-snmp-agent-includes.h>
//
// This header deliberately contains ZERO net-snmp includes and ZERO
// forward declarations for net-snmp types.  Every previous attempt to
// forward-declare netsnmp_* structs or guard typedef re-definitions with
// macros failed because:
//   • The macro net-snmp uses to guard net-snmp-config.h differs by
//     distro and version (NETSNMP_NET_SNMP_CONFIG_H, __NETSNMP_..., etc.)
//   • Any #ifndef guard we invent will never match net-snmp's own internal
//     guard, so the typedef block runs in SnmpAgent.cpp too, causing
//     "typedef redefinition" errors that break the entire include chain.
//
// Solution: the one class method that needs net-snmp pointer types in its
// signature (oidHandlerCallback) uses void* parameters here.  The .cpp
// implementation casts them to the real netsnmp_* types internally.
// This is safe because:
//   • The callback is registered with netsnmp_create_handler_registration()
//     which accepts a C function pointer — the cast is transparent.
//   • No caller outside SnmpAgent.cpp ever invokes the callback directly.
// ---------------------------------------------------------------------------

// C++ standard library
#include <string>
#include <unordered_map>   // per-node metric store
#include <mutex>           // std::mutex, std::lock_guard
#include <thread>          // std::thread (agent event loop)
#include <atomic>          // std::atomic<bool>
#include <optional>        // std::optional<float>
#include <cstdint>         // int32_t, uint32_t, int64_t
#include <stdexcept>       // std::runtime_error
#include <memory>          // std::unique_ptr
#include <vector>          // std::vector<netsnmp_handler_registration*>

// net-snmp opaque type forward declarations (header-only isolation)
struct netsnmp_handler_registration_s;
struct netsnmp_mib_handler_s;
struct netsnmp_agent_request_info_s;
struct netsnmp_request_info_s;

// net-snmp typedef aliases (very lightweight and non-owning)
typedef netsnmp_handler_registration_s netsnmp_handler_registration;
typedef netsnmp_mib_handler_s netsnmp_mib_handler;
typedef netsnmp_agent_request_info_s netsnmp_agent_request_info;
typedef netsnmp_request_info_s netsnmp_request_info;

// Project types
#include "models/SensorData.h"   // DeviceStatus

namespace IndustrialGateway {

// =============================================================================
// SnmpAgentConfig — all runtime parameters read from gateway_config.json
// =============================================================================
struct SnmpAgentConfig {
    // Agent identity
    std::string agentName    = "iiot_gateway";  ///< Used as net-snmp app name
    int         agentPort    = 161;              ///< UDP port to listen on

    // SNMPv3 USM user credentials
    std::string securityName = "admin_sec_gw";
    std::string authPass     = "auth_password";
    std::string privPass     = "priv_password";
    std::string contextName  = "factory_context";

    // Trap destination
    std::string trapTarget   = "127.0.0.1";
    int         trapPort     = 162;

    // Enterprise OID root (as dotted-decimal string without leading dot)
    std::string enterpriseOid = "1.3.6.1.4.1.9999";

    // Agent loop interval — how long agent_check_and_process() blocks per call
    int loopTimeoutUsec = 500000;   ///< 500 ms; keeps shutdown latency low
};

// =============================================================================
// TrapType — strongly-typed enumeration of all trap events the agent can send
// =============================================================================
enum class TrapType : int {
    DEVICE_OFFLINE       = 1,
    ANOMALY_DETECTED     = 2,
    UNAUTHORIZED_DEVICE  = 3,
    REPLAY_ATTACK        = 4
};

// =============================================================================
// SnmpNodeMetrics — the in-memory SNMP MIB value cache for one device.
//
// NOTE: This is distinct from SensorData::NodeMetrics, which tracks general
// gateway metrics (lastMsgId, replayCount, totalPackets, etc.). SnmpNodeMetrics
// stores only the values needed for SNMP OID responses.
//
// All values are stored in the integer formats required by SNMP:
//   • temperature and humidity are multiplied by 10 (Gauge32) to preserve
//     one decimal place without using floating-point SNMP types.
//   • status maps DeviceStatus enum → Integer32 (0=OK … 4=OFFLINE).
//   • alertState is 0 (clear) or 1 (alert active).
//   • gasValue is raw ADC (0–1023).
// =============================================================================
struct SnmpNodeMetrics {
    int32_t  deviceStatus  = 0;      ///< DeviceStatus ordinal
    int32_t  temperature10 = 0;      ///< °C × 10  (SNMP Gauge32)
    int32_t  humidity10    = 0;      ///< %RH × 10 (SNMP Gauge32)
    int32_t  alertState    = 0;      ///< 0=clear, 1=alert
    int32_t  gasValue      = 0;      ///< raw ADC value (0–1023, SNMP Gauge32)
    bool     hasTemp       = false;  ///< false → return 0xEE (no sensor)
    bool     hasHumi       = false;  ///< false → return 0xEE (no sensor)
    bool     hasGas        = false;  ///< false → return 0xEE (no sensor / preheating)
    int64_t  lastUpdated   = 0;      ///< Gateway epoch when last written
};

// =============================================================================
// SnmpAgent
//
// Usage in main.cpp:
//
//   SnmpAgentConfig cfg;
//   cfg.securityName = "admin_sec_gw";
//   cfg.authPass     = "auth_password";
//   cfg.privPass     = "priv_password";
//   cfg.trapTarget   = "192.168.1.100";
//
//   SnmpAgent agent(cfg);
//   agent.init();          // registers OIDs, creates USM user, starts thread
//
//   // From DataProcessor / Watchdog:
//   agent.updateMetrics("ESP32_SEC_01", 25.5f, 45.2f, DeviceStatus::OPERATIONAL);
//   agent.sendTrap(TrapType::DEVICE_OFFLINE, "ESP32_SEC_01", "silent 35s");
//
//   agent.shutdown();      // stops thread, cleans up net-snmp
// =============================================================================
class SnmpAgent {
public:

    // -------------------------------------------------------------------------
    // Constructor — stores config, does NOT start the agent yet.
    // -------------------------------------------------------------------------
    explicit SnmpAgent(SnmpAgentConfig config = {});

    // -------------------------------------------------------------------------
    // Destructor — calls shutdown() if still running.
    // -------------------------------------------------------------------------
    ~SnmpAgent();

    // Non-copyable / non-movable: owns net-snmp global state
    SnmpAgent(const SnmpAgent&)            = delete;
    SnmpAgent& operator=(const SnmpAgent&) = delete;
    SnmpAgent(SnmpAgent&&)                 = delete;
    SnmpAgent& operator=(SnmpAgent&&)      = delete;

    // =========================================================================
    // Lifecycle
    // =========================================================================

    // -------------------------------------------------------------------------
    // init
    //
    // Steps:
    //   1. init_agent(agentName)       — initialise net-snmp agent library
    //   2. init_mib()                  — load base MIB definitions
    //   3. createUsmUser()             — register the SNMPv3 USM user with
    //                                    SHA auth + AES priv credentials
    //   4. registerOids()              — install scalar handler callbacks for
    //                                    all OIDs under .1.3.6.1.4.1.9999.1
    //   5. init_master_agent()         — bind to UDP port 161
    //   6. Spawn agent event-loop thread
    //
    // Throws:
    //   std::runtime_error — on any net-snmp initialisation failure
    // -------------------------------------------------------------------------
    void init();

    // -------------------------------------------------------------------------
    // shutdown
    //
    // Stops the event-loop thread, calls snmp_shutdown(), releases all
    // registered OID handlers.  Idempotent.
    // -------------------------------------------------------------------------
    void shutdown();

    // =========================================================================
    // MIB update interface
    // =========================================================================

    // -------------------------------------------------------------------------
    // updateMetrics
    //
    // Atomically updates the in-memory NodeMetrics cache for nodeId.
    // Called from DataProcessor::onRawMessage() after every accepted packet.
    // Also clears the alertState flag (a fresh OPERATIONAL reading = no alert).
    //
    // Parameters:
    //   nodeId — matches the devices.node_id column
    //   temp   — std::nullopt for non-ENV nodes
    //   humi   — std::nullopt for non-ENV nodes
    //   gas    — std::nullopt for nodes without a gas sensor; raw ADC (0–1023)
    //   status — current DeviceStatus
    // -------------------------------------------------------------------------
    void updateMetrics(const std::string&       nodeId,
                       std::optional<float>     temp,
                       std::optional<float>     humi,
                       std::optional<int32_t>   gas,
                       DeviceStatus             status);

    // -------------------------------------------------------------------------
    // setAlertState
    //
    // Sets the alertState OID for nodeId to 1 (alert active).
    // Called by sendTrap() so the NMS sees the alert flag on the next GET
    // even if the trap packet was lost (UDP is unreliable).
    // -------------------------------------------------------------------------
    void setAlertState(const std::string& nodeId, int32_t state);

    // =========================================================================
    // Trap interface
    // =========================================================================

    // -------------------------------------------------------------------------
    // sendTrap
    //
    // Sends an SNMPv3 TRAP2 (SNMPv2-style trap in an SNMPv3 envelope) to the
    // configured trap target (trapTarget:trapPort).
    //
    // The trap PDU contains:
    //   sysUpTime.0            — milliseconds since init()
    //   snmpTrapOID.0          — .1.3.6.1.4.1.9999.2.<trapType>
    //   .1.3.6.1.4.1.9999.2.0.1 — node_id OctetString
    //   .1.3.6.1.4.1.9999.2.0.2 — detail  OctetString
    //   .1.3.6.1.4.1.9999.2.0.3 — timestamp Integer32 (epoch seconds)
    //
    // SNMPv3 security:
    //   Security name  : m_config.securityName
    //   Security level : SNMP_SEC_LEVEL_AUTHPRIV  (auth + priv)
    //   Auth           : SHA
    //   Priv           : AES
    //
    // Parameters:
    //   trapType — one of the TrapType enum values
    //   nodeId   — originating device node_id (included as varbind)
    //   detail   — human-readable description of the incident
    //
    // Thread safety: acquires m_trapMutex internally; safe from any thread.
    // Never throws.
    // -------------------------------------------------------------------------
    void sendTrap(TrapType           trapType,
                  const std::string& nodeId,
                  const std::string& detail = "");

    // =========================================================================
    // Status
    // =========================================================================
    bool     isRunning()      const noexcept;
    uint64_t getTrapsSent()   const noexcept;   ///< total traps dispatched
    size_t   getNodeCount()   const noexcept;   ///< nodes in MIB cache

private:
    // =========================================================================
    // net-snmp setup helpers
    // =========================================================================

    // -------------------------------------------------------------------------
    // createUsmUser — adds the SNMPv3 USM user to the in-process user table.
    //
    // This configures:
    //   • Authentication: SHA (usmHMACSHA1AuthProtocol)
    //   • Privacy:        AES (usmAESPrivProtocol)
    //   • Passwords are converted to localised keys using the engine ID.
    //
    // Called once from init(), before init_master_agent().
    // Throws std::runtime_error if user creation fails.
    // -------------------------------------------------------------------------
    void createUsmUser();

    // -------------------------------------------------------------------------
    // registerOids — installs scalar MIB handler callbacks.
    //
    // For each nodeIndex (1-based slot in m_nodeIndex map):
    //   Registers 4 OID leaves under .1.3.6.1.4.1.9999.1.<nodeIndex>.*
    //   Each leaf gets a static C-style handler (getHandler_*) that reads
    //   from the m_metricsCache map under m_metricsMutex.
    //
    // Note: net-snmp's registration API is C-based and uses raw callbacks.
    // We use a static trampoline pattern: the handler function receives a
    // pointer to a netsnmp_handler_registration that carries a void* magic
    // pointer back to the SnmpAgent instance.
    // -------------------------------------------------------------------------
    void registerOids();

    // -------------------------------------------------------------------------
    // buildTrapOid — converts a TrapType to the full OID string for the trap.
    // e.g. TrapType::DEVICE_OFFLINE → "1.3.6.1.4.1.9999.2.1"
    // -------------------------------------------------------------------------
    std::string buildTrapOid(TrapType t) const;

    // -------------------------------------------------------------------------
    // trapTypeToString — human label for log messages.
    // -------------------------------------------------------------------------
    static std::string trapTypeToString(TrapType t);

    // -------------------------------------------------------------------------
    // getOrCreateNodeIndex — returns the 1-based integer index for a nodeId,
    // creating a new entry in m_nodeIndex if this is the first time we've
    // seen this nodeId.  Called under m_metricsMutex.
    // -------------------------------------------------------------------------
    int getOrCreateNodeIndex(const std::string& nodeId);

    // =========================================================================
    // Static OID handler trampoline
    //
    // net-snmp requires a plain C function pointer for MIB handler callbacks.
    // The four parameters are net-snmp internal types (netsnmp_mib_handler*,
    // netsnmp_handler_registration*, etc.) that must NOT appear in this header
    // (see isolation note at the top of the file).
    //
    // The signature here uses void* for all four parameters.  In SnmpAgent.cpp
    // the function is defined with the real net-snmp types and registered via
    // a reinterpret_cast to the Netsnmp_Node_Handler function-pointer typedef.
    // This is safe because the callback is only ever invoked by net-snmp's own
    // dispatcher — no external code calls it directly.
    // =========================================================================
    static int oidHandlerCallback(void* handler,
                                  void* reginfo,
                                  void* reqinfo,
                                  void* requests);

    // Allow the internal C-style SNMP callback implementation to access
    // the agent's private caches for safe lock-protected reads.
    friend int oidHandlerImpl(netsnmp_mib_handler*          handler,
                              netsnmp_handler_registration* reginfo,
                              netsnmp_agent_request_info*   reqinfo,
                              netsnmp_request_info*         requests);

    // =========================================================================
    // Agent event-loop thread
    // =========================================================================
    void agentLoop();   ///< Entry point for m_agentThread

    // =========================================================================
    // Logging
    // =========================================================================
    static std::string nowStr();

    // =========================================================================
    // Member variables
    // =========================================================================

    SnmpAgentConfig  m_config;        ///< Runtime parameters (read-only after init)

    // ── Threading ─────────────────────────────────────────────────────────────
    std::thread       m_agentThread;  ///< Runs the net-snmp event loop
    std::atomic<bool> m_running;      ///< false → agentLoop() exits

    // ── MIB value cache ───────────────────────────────────────────────────────
    // Key   : nodeId string  (e.g. "ESP32_SEC_01")
    // Value : SnmpNodeMetrics struct with the latest SNMP-encodable values
    mutable std::mutex                                  m_metricsMutex;
    std::unordered_map<std::string, SnmpNodeMetrics>   m_metricsCache;

    // Monotonic node index: nodeId → 1-based integer (MIB table row number)
    // Assigned in insertion order; stable for the life of the process.
    std::unordered_map<std::string, int>           m_nodeIndex;
    int                                             m_nextNodeIndex = 1;

    // ── Trap serialisation ────────────────────────────────────────────────────
    mutable std::mutex  m_trapMutex;      ///< Serialises sendTrap() calls
    std::atomic<uint64_t> m_trapsSent;    ///< Total traps dispatched

    // ── Startup timestamp (for sysUpTime varbind) ─────────────────────────────
    int64_t m_startEpoch;   ///< Unix epoch seconds when init() was called

    // ── Registered handler list (for cleanup in shutdown()) ───────────────────
    // Stored as opaque net-snmp structure pointers. SnmpAgent.cpp owns and
    // manipulates the pointers using the net-snmp API.
    std::vector<netsnmp_handler_registration*> m_registrations;
};

} // namespace IndustrialGateway

#endif // IIOT_GATEWAY_SNMP_AGENT_H 