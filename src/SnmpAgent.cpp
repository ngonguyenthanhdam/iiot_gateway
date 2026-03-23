// =============================================================================
// SnmpAgent.cpp — SNMPv3 Agent & Trap Sender Implementation
// Industrial IoT Gateway Security Platform
// Standard : C++17
//
// net-snmp API notes:
//   • The entire net-snmp agent state is global (C library design).
//     Only ONE SnmpAgent instance may exist per process.
//   • OID handler callbacks are C-style function pointers; we use a
//     static trampoline that recovers the C++ instance via magic pointer.
//   • All net-snmp calls happen from the agentLoop() thread EXCEPT for
//     metric writes and trap sends, which are thread-safe via mutexes.
// =============================================================================

// ---------------------------------------------------------------------------
// net-snmp headers — must be included FIRST, in this exact order, and only
// in this .cpp file.  Including them in SnmpAgent.h would propagate the
// agent API macros into every translation unit, causing cascading errors.
//
// Mandatory order required by net-snmp:
//   1. net-snmp-config.h   — feature-test macros and platform detection
//   2. net-snmp-includes.h — core types: oid, u_char, netsnmp_session, etc.
//   3. net-snmp-agent-includes.h — agent API: handler registration, MIB ops
// ---------------------------------------------------------------------------
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/library/snmpusm.h>

#include "SnmpAgent.h"

// C standard library (needed for net-snmp internals)
#include <cstring>      // memcpy, memset
#include <cstdio>       // snprintf
#include <optional>
#include <atomic>

// C++ standard library
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <stdexcept>
#include <algorithm>    // min
#include <vector>
#include <thread>       // std::thread — required for m_agentThread
#include <mutex>        // std::mutex, std::lock_guard — required for m_metricsMutex

using namespace std;

namespace IndustrialGateway {

// =============================================================================
// Anonymous namespace — file-scope helpers
// =============================================================================
namespace {

// Numeric OID arrays for the enterprise root and key sub-branches.
// Using hardcoded arrays is the standard net-snmp pattern; avoid
// parse_oid() in performance paths as it does string parsing at runtime.

// .1.3.6.1.4.1.9999    — enterprise root
static const oid k_enterpriseRoot[] = { 1,3,6,1,4,1,9999 };
static const size_t k_enterpriseRootLen = OID_LENGTH(k_enterpriseRoot);

// .1.3.6.1.4.1.9999.1  — sensor data branch
static const oid k_sensorBranch[] = { 1,3,6,1,4,1,9999,1 };
static const size_t k_sensorBranchLen = OID_LENGTH(k_sensorBranch);

// .1.3.6.1.4.1.9999.2  — trap branch
static const oid k_trapBranch[] = { 1,3,6,1,4,1,9999,2 };

// sysUpTime OID — required first varbind in every TRAP2 PDU
static const oid k_sysUpTime[]  = { 1,3,6,1,2,1,1,3,0 };
static const size_t k_sysUpTimeLen = OID_LENGTH(k_sysUpTime);

// snmpTrapOID — required second varbind in every TRAP2 PDU
static const oid k_snmpTrapOid[] = { 1,3,6,1,6,3,1,1,4,1,0 };
static const size_t k_snmpTrapOidLen = OID_LENGTH(k_snmpTrapOid);

// OID column indices under .1.3.6.1.4.1.9999.1.<nodeIndex>
constexpr oid k_colStatus  = 1;
constexpr oid k_colTemp    = 2;
constexpr oid k_colHumi    = 3;
constexpr oid k_colAlert   = 4;

// ── OID handler context ───────────────────────────────────────────────────────
// Passed as the "magic" void* in each handler registration so the static
// callback can find the correct SnmpAgent instance and the node/column it serves.
struct HandlerContext {
    SnmpAgent* agent;     // back-pointer to the C++ instance
    string nodeId;   // node_id this handler serves
    oid column;           // k_colStatus / k_colTemp / k_colHumi / k_colAlert
};

} // anonymous namespace

// =============================================================================
// nowStr() — UTC timestamp string (kept as a static member implementation)
// =============================================================================
string SnmpAgent::nowStr() {
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    ostringstream oss;
    oss << "[" << put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << " UTC]";
    return oss.str();
}

// =============================================================================
// Constructor & Destructor
// =============================================================================

SnmpAgent::SnmpAgent(SnmpAgentConfig config)
    : m_config(move(config))
    , m_running(false)
    , m_nextNodeIndex(1)
    , m_trapsSent(0)
    , m_startEpoch(0)
{}

SnmpAgent::~SnmpAgent() {
    shutdown();
}

// =============================================================================
// Lifecycle
// =============================================================================

// -----------------------------------------------------------------------------
// init — full SNMPv3 agent startup sequence
//
// Order matters in net-snmp:
//   1. netsnmp_ds_set_boolean(AGENT, NO_ROOT_ACCESS, 1)
//      → Run as non-root (sub-agent or user-space agent mode).
//   2. init_agent(name)
//      → Initialises internal data structures, installs signal handlers.
//   3. init_mib()
//      → Loads the RFC MIBs (required for OID name resolution).
//   4. createUsmUser()
//      → Adds the SNMPv3 USM user BEFORE init_master_agent() so the user
//        is available when the first GET arrives.
//   5. registerOids()
//      → Installs our custom scalar handlers.
//   6. init_master_agent()
//      → Binds to UDP 161, starts accepting PDUs.
//   7. Spawn agentLoop() thread.
// -----------------------------------------------------------------------------
void SnmpAgent::init() {
    cout << nowStr() << " [SNMP] Initialising SNMPv3 agent...\n";

    // Record start time for sysUpTime calculation
    m_startEpoch = static_cast<int64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    // ── Step 1: Configure agent to run without root privileges ───────────────
    // NETSNMP_DS_AGENT_ROLE = 1 means "master agent" (not a sub-agent).
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_ROLE, 1);

    // Set the agent listening port (default 161)
    string portStr = "udp:" + to_string(m_config.agentPort);
    netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                          NETSNMP_DS_AGENT_PORTS,
                          portStr.c_str());

    // Disable logging to stderr from net-snmp internals (we do our own logging)
    snmp_disable_log();
    snmp_enable_calllog();   // Redirect to our callback (we register none = silent)

    // ── Step 2: Initialise the net-snmp agent core ────────────────────────────
    int rc = init_agent(m_config.agentName.c_str());
    if (rc != 0) {
        throw runtime_error(
            "[SnmpAgent] init_agent() failed with rc=" + to_string(rc)
        );
    }
    cout << nowStr() << " [SNMP] init_agent() OK\n";

    // ── Step 3: Load base MIB definitions ────────────────────────────────────
    init_mib();
    cout << nowStr() << " [SNMP] MIBs loaded.\n";

    // ── Step 4: Create the SNMPv3 USM user ───────────────────────────────────
    createUsmUser();

    // ── Step 5: Register our enterprise OIDs ─────────────────────────────────
    registerOids();

    // ── Step 6: Bind to UDP port and start accepting PDUs ────────────────────
    rc = init_master_agent();
    if (rc != 0) {
        throw runtime_error(
            "[SnmpAgent] init_master_agent() failed with rc=" +
            to_string(rc) +
            " — is port " + to_string(m_config.agentPort) + " in use?"
        );
    }
    cout << nowStr() << " [SNMP] Agent listening on UDP port "
              << m_config.agentPort << "\n";

    // ── Step 7: Spawn the event-loop thread ──────────────────────────────────
    m_running.store(true);
    m_agentThread = thread([this]() { agentLoop(); });

    cout << nowStr() << " [SNMP] Agent initialised and running.\n"
              << "  Security name  : " << m_config.securityName  << "\n"
              << "  Auth protocol  : SHA\n"
              << "  Priv protocol  : AES\n"
              << "  Context name   : " << m_config.contextName    << "\n"
              << "  Trap target    : " << m_config.trapTarget
              << ":" << m_config.trapPort << "\n"
              << "  Enterprise OID : " << m_config.enterpriseOid  << "\n";
}

// -----------------------------------------------------------------------------
// shutdown
// -----------------------------------------------------------------------------
void SnmpAgent::shutdown() {
    bool wasRunning = m_running.exchange(false);

    if (wasRunning && m_agentThread.joinable()) {
        cout << nowStr() << " [SNMP] Shutting down agent thread...\n";
        m_agentThread.join();
        cout << nowStr() << " [SNMP] Agent thread joined.\n";
    }

    // Deregister all OID handlers
    for (auto* reg : m_registrations) {
        if (reg) {
            netsnmp_unregister_handler(reg);
        }
    }
    m_registrations.clear();

    // net-snmp global cleanup
    snmp_shutdown(m_config.agentName.c_str());
    cout << nowStr() << " [SNMP] Agent shut down. Traps sent: "
              << m_trapsSent.load() << "\n";
}

// =============================================================================
// net-snmp setup helpers
// =============================================================================

// -----------------------------------------------------------------------------
// createUsmUser
//
// Adds the SNMPv3 user to the in-process USM user table using the net-snmp
// usmUser API.
//
// Key net-snmp types:
//   struct usmUser           — one USM user entry
//   usmHMACSHA1AuthProtocol  — SHA-1 authentication (RFC 3414)
//   usmAESPrivProtocol       — AES-128 privacy (RFC 3826)
//
// The password-to-key derivation (RFC 2574 §2.6) is done by
// generate_Ku() which produces a localised key from the plain-text password
// and the engine's "authKey" / "privKey" buffers.
//
// IMPORTANT: The user must be added BEFORE init_master_agent() is called.
// -----------------------------------------------------------------------------
void SnmpAgent::createUsmUser() {
    cout << nowStr() << " [SNMP] Creating USM user '"
              << m_config.securityName << "'...\n";

    // Allocate a new USM user struct (net-snmp will own this memory)
    struct usmUser* user = usm_new_user();
    if (!user) {
        throw runtime_error(
            "[SnmpAgent] usm_new_user() returned null"
        );
    }

    // ── Security name (username) ──────────────────────────────────────────────
    user->name        = strdup(m_config.securityName.c_str());
    user->secName     = strdup(m_config.securityName.c_str());

    // ── Authentication protocol: SHA-1 ───────────────────────────────────────
    user->authProtocol =
        snmp_duplicate_objid(usmHMACSHA1AuthProtocol,
                             USM_LENGTH_OID_TRANSFORM);
    user->authProtocolLen = USM_LENGTH_OID_TRANSFORM;

    // Derive the localised authentication key from the plain-text password.
    // generate_Ku() implements RFC 2574 §2.6 (password-to-key algorithm).
    size_t authKeyLen = USM_AUTH_KU_LEN;
    user->authKey = static_cast<u_char*>(malloc(authKeyLen));
    if (!user->authKey) {
        usm_free_user(user);
        throw runtime_error("[SnmpAgent] malloc authKey failed");
    }

    int rc = generate_Ku(usmHMACSHA1AuthProtocol,
                         USM_LENGTH_OID_TRANSFORM,
                         reinterpret_cast<const u_char*>(m_config.authPass.c_str()),
                         m_config.authPass.size(),
                         user->authKey,
                         &authKeyLen);
    if (rc != SNMPERR_SUCCESS) {
        usm_free_user(user);
        throw runtime_error(
            "[SnmpAgent] generate_Ku(auth) failed, rc=" + to_string(rc)
        );
    }
    user->authKeyLen = authKeyLen;

    // ── Privacy protocol: AES-128 ─────────────────────────────────────────────
    user->privProtocol =
        snmp_duplicate_objid(usmAESPrivProtocol,
                             USM_LENGTH_OID_TRANSFORM);
    user->privProtocolLen = USM_LENGTH_OID_TRANSFORM;

    // Derive the localised privacy key from the plain-text privacy password.
    size_t privKeyLen = USM_PRIV_KU_LEN;
    user->privKey = static_cast<u_char*>(malloc(privKeyLen));
    if (!user->privKey) {
        usm_free_user(user);
        throw runtime_error("[SnmpAgent] malloc privKey failed");
    }

    rc = generate_Ku(usmHMACSHA1AuthProtocol,  // AES key derivation also uses SHA
                     USM_LENGTH_OID_TRANSFORM,
                     reinterpret_cast<const u_char*>(m_config.privPass.c_str()),
                     m_config.privPass.size(),
                     user->privKey,
                     &privKeyLen);
    if (rc != SNMPERR_SUCCESS) {
        usm_free_user(user);
        throw runtime_error(
            "[SnmpAgent] generate_Ku(priv) failed, rc=" + to_string(rc)
        );
    }
    user->privKeyLen = privKeyLen;

    // ── Add user to the global USM table ──────────────────────────────────────
    // usm_add_user() takes ownership of the user struct.
    if (usm_add_user(user) == NULL) {
        // usm_add_user can return NULL if the user already exists (idempotent)
        cerr << nowStr()
                  << " [SNMP] WARNING: usm_add_user() returned NULL"
                     " (user may already exist)\n";
    }

    cout << nowStr() << " [SNMP] USM user '" << m_config.securityName
              << "' created (SHA auth, AES priv).\n";
}

// -----------------------------------------------------------------------------
// registerOids
//
// The OID layout we register:
//
//   .1.3.6.1.4.1.9999.1.<nodeIndex>.1  — device_status  (Integer32)
//   .1.3.6.1.4.1.9999.1.<nodeIndex>.2  — temperature    (Gauge32 × 10)
//   .1.3.6.1.4.1.9999.1.<nodeIndex>.3  — humidity       (Gauge32 × 10)
//   .1.3.6.1.4.1.9999.1.<nodeIndex>.4  — alert_state    (Integer32)
//
// net-snmp registration pattern:
//   netsnmp_handler_registration* reg =
//       netsnmp_create_handler_registration(name, handler_fn, oid, oid_len,
//                                           HANDLER_CAN_RONLY);
//   reg->my_reg_void = context_ptr;   ← carry our instance + column info
//   netsnmp_register_scalar(reg);
//
// Because we don't know the node list at init() time (nodes may connect after
// startup), we pre-register OID slots for a fixed maximum number of nodes and
// populate them on demand.  We use nodeIndex 1–16 (16 simultaneous nodes).
//
// In production a proper MIB table (netsnmp_table_data) would be used.
// For this project, pre-allocated scalar slots keep the code much simpler
// while still satisfying the spec requirements.
// -----------------------------------------------------------------------------
void SnmpAgent::registerOids() {
    constexpr int k_maxNodes = 16;

    cout << nowStr() << " [SNMP] Registering OIDs for up to "
              << k_maxNodes << " nodes...\n";

    for (int nodeIdx = 1; nodeIdx <= k_maxNodes; ++nodeIdx) {
        for (oid col : { k_colStatus, k_colTemp, k_colHumi, k_colAlert }) {

            // Build the full OID: .1.3.6.1.4.1.9999.1.<nodeIdx>.<col>
            oid fullOid[MAX_OID_LEN];
            size_t fullOidLen = k_sensorBranchLen;
            memcpy(fullOid, k_sensorBranch, k_sensorBranchLen * sizeof(oid));
            fullOid[fullOidLen++] = static_cast<oid>(nodeIdx);
            fullOid[fullOidLen++] = col;

            // Build a unique registration name for diagnostics
            string regName = "iiot.node" + to_string(nodeIdx) +
                                  ".col"      + to_string(col);

            // Allocate the handler context — net-snmp callback will use this
            // to look up the correct node and column.
            // We use a raw new here because net-snmp stores the pointer as
            // void* and we must ensure it outlives the handler registration.
            // These are freed in shutdown() when we unregister.
            auto* ctx = new HandlerContext{
                this,
                "",      // nodeId is resolved at GET time via nodeIndex
                col
            };
            // Store the nodeIndex in the context via a separate field added
            // as the last byte of nodeId for simplicity. We encode as decimal.
            ctx->nodeId = to_string(nodeIdx);

            // Create the handler registration
            netsnmp_handler_registration* reg =
                netsnmp_create_handler_registration(
                    regName.c_str(),
                    SnmpAgent::oidHandlerCallback,
                    fullOid,
                    fullOidLen,
                    HANDLER_CAN_RONLY    // read-only scalars
                );

            if (!reg) {
                delete ctx;
                cerr << nowStr()
                          << " [SNMP] WARNING: Failed to create handler for "
                          << regName << "\n";
                continue;
            }

            // Attach our context so the callback can find the data
            reg->my_reg_void = static_cast<void*>(ctx);

            // Register as a scalar OID
            int rc = netsnmp_register_scalar(reg);
            if (rc != MIB_REGISTERED_OK) {
                delete ctx;
                cerr << nowStr()
                          << " [SNMP] WARNING: netsnmp_register_scalar failed"
                             " for " << regName
                          << " rc=" << rc << "\n";
            } else {
                m_registrations.push_back(reg);
            }
        }
    }

    cout << nowStr() << " [SNMP] Registered "
              << m_registrations.size() << " OID handlers.\n";
}

// =============================================================================
// OID handler callback (static trampoline)
//
// Called by net-snmp from the agentLoop() thread whenever it processes an
// incoming GET / GETNEXT / GETBULK PDU for one of our registered OIDs.
//
// The callback is C-style (required by net-snmp).  We recover the C++ instance
// via reginfo->my_reg_void (cast to HandlerContext*).
//
// Response encoding:
//   device_status / alert_state  → ASN_INTEGER   (snmp_set_var_typed_integer)
//   temperature / humidity       → ASN_GAUGE      (Gauge32 — unsigned 32-bit)
//
//   If the node index has no corresponding entry in m_metricsCache, we return
//   the sentinel value 0xEE (238) to signal "hardware error / no data".
//   This matches the 0xEE convention described in the spec.
// =============================================================================
int SnmpAgent::oidHandlerCallback(netsnmp_mib_handler*          handler,
                                  netsnmp_handler_registration* reginfo,
                                  netsnmp_agent_request_info*   reqinfo,
                                  netsnmp_request_info*         requests)
{
    // Only handle GET operations (GETNEXT is handled by net-snmp internally
    // for scalar OIDs registered with netsnmp_register_scalar).
    if (reqinfo->mode != MODE_GET) {
        return SNMP_ERR_NOERROR;
    }

    // Recover our context from the registration
    if (!reginfo || !reginfo->my_reg_void) {
        netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
        return SNMP_ERR_GENERR;
    }

    auto* ctx   = static_cast<HandlerContext*>(reginfo->my_reg_void);
    SnmpAgent* self = ctx->agent;
    int nodeIdx = stoi(ctx->nodeId);   // 1-based slot index
    oid column  = ctx->column;

    // Look up the nodeId for this index slot
    string nodeId;
    NodeMetrics metrics{};
    bool found = false;

    {
        lock_guard<mutex> lock(self->m_metricsMutex);
        for (const auto& [nid, idx] : self->m_nodeIndex) {
            if (idx == nodeIdx) {
                nodeId = nid;
                auto it = self->m_metricsCache.find(nid);
                if (it != self->m_metricsCache.end()) {
                    metrics = it->second;
                    found   = true;
                }
                break;
            }
        }
    }

    // Sentinel for unallocated node slots or sensors not fitted
    constexpr long k_noData = 0xEE;

    if (!found) {
        // Slot not yet assigned to a live node — return sentinel
        snmp_set_var_typed_integer(requests->requestvb,
                                   ASN_INTEGER,
                                   k_noData);
        return SNMP_ERR_NOERROR;
    }

    // Encode the requested column
    switch (column) {
        case k_colStatus: {
            // Integer32: DeviceStatus ordinal (0=OPERATIONAL … 4=OFFLINE)
            snmp_set_var_typed_integer(requests->requestvb,
                                       ASN_INTEGER,
                                       static_cast<long>(metrics.deviceStatus));
            break;
        }
        case k_colTemp: {
            // Gauge32: temperature × 10, or 0xEE if no sensor
            long val = metrics.hasTemp ? static_cast<long>(metrics.temperature10)
                                       : k_noData;
            snmp_set_var_typed_integer(requests->requestvb,
                                       ASN_GAUGE,
                                       val);
            break;
        }
        case k_colHumi: {
            // Gauge32: humidity × 10, or 0xEE if no sensor
            long val = metrics.hasHumi ? static_cast<long>(metrics.humidity10)
                                       : k_noData;
            snmp_set_var_typed_integer(requests->requestvb,
                                       ASN_GAUGE,
                                       val);
            break;
        }
        case k_colAlert: {
            // Integer32: 0=clear, 1=alert active
            snmp_set_var_typed_integer(requests->requestvb,
                                       ASN_INTEGER,
                                       static_cast<long>(metrics.alertState));
            break;
        }
        default:
            netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOSUCHNAME);
            return SNMP_ERR_NOSUCHNAME;
    }

    return SNMP_ERR_NOERROR;
}

// =============================================================================
// MIB update interface
// =============================================================================

// -----------------------------------------------------------------------------
// updateMetrics
//
// Converts the floating-point sensor values to integer SNMP encodings and
// writes them into the m_metricsCache map under m_metricsMutex.
//
// Temperature and humidity are stored as Gauge32 (×10) to preserve one
// decimal place.  SNMP does not have a native float type; this is the
// standard industry convention for environmental data in SNMP MIBs.
//
// Example:  25.5°C  → Gauge32 = 255
//           45.2%RH → Gauge32 = 452
// -----------------------------------------------------------------------------
void SnmpAgent::updateMetrics(const string&       nodeId,
                               optional<float>     temp,
                               optional<float>     humi,
                               DeviceStatus             status)
{
    lock_guard<mutex> lock(m_metricsMutex);

    // Ensure this node has an index slot
    getOrCreateNodeIndex(nodeId);

    NodeMetrics& m = m_metricsCache[nodeId];

    // Device status: map enum ordinal directly
    m.deviceStatus = static_cast<int32_t>(status);

    // Temperature: multiply by 10, clamp to Gauge32 range [0, 4294967295]
    if (temp.has_value()) {
        // Clamp negative temps to 0 for Gauge32 (unsigned).
        // Real-world factory sensors shouldn't report < 0 °C as OPERATIONAL,
        // but we guard against it to prevent integer underflow.
        float t = *temp;
        m.temperature10 = (t < 0.0f)
                           ? 0
                           : static_cast<int32_t>(t * 10.0f + 0.5f);  // round
        m.hasTemp = true;
    } else {
        m.hasTemp = false;
    }

    // Humidity: multiply by 10
    if (humi.has_value()) {
        float h = *humi;
        m.humidity10 = (h < 0.0f)
                        ? 0
                        : static_cast<int32_t>(h * 10.0f + 0.5f);
        m.hasHumi = true;
    } else {
        m.hasHumi = false;
    }

    // Clear alert state when an OPERATIONAL reading arrives
    if (status == DeviceStatus::OPERATIONAL) {
        m.alertState = 0;
    }

    // Stamp the gateway receipt time
    m.lastUpdated = static_cast<int64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

// -----------------------------------------------------------------------------
// setAlertState — sets alertState OID, called before/after sendTrap
// -----------------------------------------------------------------------------
void SnmpAgent::setAlertState(const string& nodeId, int32_t state) {
    lock_guard<mutex> lock(m_metricsMutex);
    getOrCreateNodeIndex(nodeId);
    m_metricsCache[nodeId].alertState = state;
}

// =============================================================================
// Trap interface
// =============================================================================

// -----------------------------------------------------------------------------
// sendTrap
//
// Constructs and dispatches an SNMPv3 TRAP2 PDU to the NMS.
//
// PDU construction follows RFC 3416 §4.2.6 (SNMPv2-Trap-PDU):
//
//   VarBind[0]: sysUpTime.0          — timeticks (centiseconds since init)
//   VarBind[1]: snmpTrapOID.0        — OID of this specific trap
//   VarBind[2]: .9999.2.0.1 / node   — OctetString: originating node_id
//   VarBind[3]: .9999.2.0.2 / detail — OctetString: incident description
//   VarBind[4]: .9999.2.0.3 / ts     — Integer32: Unix epoch timestamp
//
// SNMPv3 envelope:
//   Security model : USM (User-based Security Model)
//   Security level : authPriv (SNMP_SEC_LEVEL_AUTHPRIV)
//   Auth           : SHA-1
//   Priv           : AES-128
//
// The session is opened fresh for each trap (not cached) because:
//   a) Traps are rare (security events only)
//   b) A cached session could fail silently on network change
//   c) net-snmp session state is not thread-safe without re-entrancy guards
//
// The m_trapMutex ensures only one trap is in-flight at a time (net-snmp's
// snmp_send() is not re-entrant when sharing the same session).
// -----------------------------------------------------------------------------
void SnmpAgent::sendTrap(TrapType           trapType,
                          const string& nodeId,
                          const string& detail)
{
    lock_guard<mutex> lock(m_trapMutex);

    cout << nowStr()
              << " [SNMP] Sending TRAP: " << trapTypeToString(trapType)
              << " node='" << nodeId << "'\n";

    // ── Set alert flag in MIB cache ───────────────────────────────────────────
    setAlertState(nodeId, 1);

    // ── Open a dedicated SNMP session to the trap target ─────────────────────
    struct snmp_session sessionParams;
    snmp_sess_init(&sessionParams);

    // SNMPv3
    sessionParams.version       = SNMP_VERSION_3;

    // Peer address: "udp:<ip>:<port>"
    string peerName = "udp:" + m_config.trapTarget +
                           ":" + to_string(m_config.trapPort);
    sessionParams.peername = const_cast<char*>(peerName.c_str());

    // Security name (username)
    sessionParams.securityName    =
        const_cast<char*>(m_config.securityName.c_str());
    sessionParams.securityNameLen = m_config.securityName.size();

    // Security level: authPriv — both authentication and encryption required
    sessionParams.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

    // Authentication: SHA-1
    sessionParams.securityAuthProto    =
        const_cast<oid*>(usmHMACSHA1AuthProtocol);
    sessionParams.securityAuthProtoLen = USM_LENGTH_OID_TRANSFORM;

    // Copy the auth passphrase into the session for key derivation
    sessionParams.securityAuthKeyLen = USM_AUTH_KU_LEN;
    memset(sessionParams.securityAuthKey, 0, USM_AUTH_KU_LEN);
    size_t authKeyLen = USM_AUTH_KU_LEN;
    generate_Ku(usmHMACSHA1AuthProtocol,
                USM_LENGTH_OID_TRANSFORM,
                reinterpret_cast<const u_char*>(m_config.authPass.c_str()),
                m_config.authPass.size(),
                sessionParams.securityAuthKey,
                &authKeyLen);
    sessionParams.securityAuthKeyLen = authKeyLen;

    // Privacy: AES-128
    sessionParams.securityPrivProto    =
        const_cast<oid*>(usmAESPrivProtocol);
    sessionParams.securityPrivProtoLen = USM_LENGTH_OID_TRANSFORM;

    sessionParams.securityPrivKeyLen = USM_PRIV_KU_LEN;
    memset(sessionParams.securityPrivKey, 0, USM_PRIV_KU_LEN);
    size_t privKeyLen = USM_PRIV_KU_LEN;
    generate_Ku(usmHMACSHA1AuthProtocol,
                USM_LENGTH_OID_TRANSFORM,
                reinterpret_cast<const u_char*>(m_config.privPass.c_str()),
                m_config.privPass.size(),
                sessionParams.securityPrivKey,
                &privKeyLen);
    sessionParams.securityPrivKeyLen = privKeyLen;

    // Open the session — returns an opaque handle
    struct snmp_session* sess = snmp_open(&sessionParams);
    if (!sess) {
        int liberr, syserr;
        char* errstr = nullptr;
        snmp_error(&sessionParams, &liberr, &syserr, &errstr);
        cerr << nowStr()
                  << " [SNMP] sendTrap: snmp_open() failed: "
                  << (errstr ? errstr : "unknown")
                  << " (liberr=" << liberr << " syserr=" << syserr << ")\n";
        if (errstr) free(errstr);
        return;   // Non-fatal: trap delivery failed, but gateway continues
    }

    // ── Build the TRAP2 PDU ───────────────────────────────────────────────────
    netsnmp_pdu* pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    if (!pdu) {
        snmp_close(sess);
        cerr << nowStr() << " [SNMP] sendTrap: snmp_pdu_create failed\n";
        return;
    }

    // ── VarBind 0: sysUpTime.0 ───────────────────────────────────────────────
    // Value: timeticks = centiseconds since agent init()
    int64_t nowEp = static_cast<int64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    u_long uptimeCentisec = static_cast<u_long>((nowEp - m_startEpoch) * 100);
    snmp_add_var(pdu,
                 k_sysUpTime,
                 k_sysUpTimeLen,
                 't',   // timeticks
                 to_string(uptimeCentisec).c_str());

    // ── VarBind 1: snmpTrapOID.0 ─────────────────────────────────────────────
    // Value: the specific trap OID for this event type
    string trapOidStr = buildTrapOid(trapType);
    snmp_add_var(pdu,
                 k_snmpTrapOid,
                 k_snmpTrapOidLen,
                 'o',   // OID
                 trapOidStr.c_str());

    // ── VarBind 2: node_id (OctetString) ─────────────────────────────────────
    // OID: .1.3.6.1.4.1.9999.2.0.1
    oid nodeOid[] = { 1,3,6,1,4,1,9999,2,0,1 };
    snmp_add_var(pdu,
                 nodeOid,
                 OID_LENGTH(nodeOid),
                 's',   // OctetString
                 nodeId.c_str());

    // ── VarBind 3: detail string (OctetString) ────────────────────────────────
    // OID: .1.3.6.1.4.1.9999.2.0.2
    oid detailOid[] = { 1,3,6,1,4,1,9999,2,0,2 };
    // Truncate detail to 255 chars — SNMP OctetString is bounded
    string detailTrunc = detail.substr(0, 255);
    snmp_add_var(pdu,
                 detailOid,
                 OID_LENGTH(detailOid),
                 's',
                 detailTrunc.c_str());

    // ── VarBind 4: Unix timestamp (Integer32) ─────────────────────────────────
    // OID: .1.3.6.1.4.1.9999.2.0.3
    oid tsOid[] = { 1,3,6,1,4,1,9999,2,0,3 };
    snmp_add_var(pdu,
                 tsOid,
                 OID_LENGTH(tsOid),
                 'i',   // Integer32
                 to_string(nowEp).c_str());

    // ── Send the PDU ──────────────────────────────────────────────────────────
    int sendRc = snmp_send(sess, pdu);
    if (sendRc == 0) {
        // snmp_send returns 0 on failure; snmp_perror prints the error
        int liberr, syserr;
        char* errstr = nullptr;
        snmp_error(&sessionParams, &liberr, &syserr, &errstr);
        cerr << nowStr()
                  << " [SNMP] sendTrap: snmp_send() failed: "
                  << (errstr ? errstr : "unknown") << "\n";
        if (errstr) free(errstr);
        snmp_free_pdu(pdu);   // must free PDU on send failure
    } else {
        // On success, snmp_send() takes ownership of pdu — do NOT free it
        m_trapsSent.fetch_add(1, memory_order_relaxed);
        cout << nowStr()
                  << " [SNMP] ✓ TRAP sent: " << trapTypeToString(trapType)
                  << " → " << m_config.trapTarget
                  << ":" << m_config.trapPort
                  << " (total=" << m_trapsSent.load() << ")\n";
    }

    snmp_close(sess);
}

// =============================================================================
// Agent event loop
// =============================================================================

// -----------------------------------------------------------------------------
// agentLoop
//
// Runs on the dedicated m_agentThread.
// agent_check_and_process(1) blocks for up to loopTimeoutUsec microseconds
// waiting for an incoming SNMP PDU, then processes it and returns.
// This gives us a regular "wake-up" window to check m_running.
//
// Using 1 (blocking) rather than 0 (non-blocking) avoids a busy-wait loop
// that would consume 100% of one Pi4 CPU core.
// -----------------------------------------------------------------------------
void SnmpAgent::agentLoop() {
    cout << nowStr() << " [SNMP] Agent event loop started.\n";

    // Set the agent's select() timeout via NETSNMP_DS
    netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
                       NETSNMP_DS_AGENT_CACHE_TIMEOUT,
                       m_config.loopTimeoutUsec / 1000000);

    while (m_running.load(memory_order_acquire)) {
        // Process one round of incoming SNMP requests.
        // The '1' parameter means "block until data or timeout".
        agent_check_and_process(1);
    }

    cout << nowStr() << " [SNMP] Agent event loop exited.\n";
}

// =============================================================================
// Private helpers
// =============================================================================

// -----------------------------------------------------------------------------
// getOrCreateNodeIndex — called under m_metricsMutex
// -----------------------------------------------------------------------------
int SnmpAgent::getOrCreateNodeIndex(const string& nodeId) {
    auto it = m_nodeIndex.find(nodeId);
    if (it != m_nodeIndex.end()) {
        return it->second;
    }
    // Assign the next available slot (1-based)
    int idx = m_nextNodeIndex++;
    m_nodeIndex[nodeId] = idx;
    cout << nowStr()
              << " [SNMP] Assigned node '" << nodeId
              << "' to MIB index " << idx << "\n";
    return idx;
}

// -----------------------------------------------------------------------------
// buildTrapOid — ".enterpriseOid.2.<trapType>"
// -----------------------------------------------------------------------------
string SnmpAgent::buildTrapOid(TrapType t) const {
    return m_config.enterpriseOid + ".2." + to_string(static_cast<int>(t));
}

// -----------------------------------------------------------------------------
// trapTypeToString — human-readable labels for log output
// -----------------------------------------------------------------------------
string SnmpAgent::trapTypeToString(TrapType t) {
    switch (t) {
        case TrapType::DEVICE_OFFLINE:      return "DEVICE_OFFLINE";
        case TrapType::ANOMALY_DETECTED:    return "ANOMALY_DETECTED";
        case TrapType::UNAUTHORIZED_DEVICE: return "UNAUTHORIZED_DEVICE";
        case TrapType::REPLAY_ATTACK:       return "REPLAY_ATTACK";
        default:                            return "UNKNOWN_TRAP";
    }
}

// -----------------------------------------------------------------------------
// isRunning / getTrapsSent / getNodeCount — lock-free reads
// -----------------------------------------------------------------------------
bool SnmpAgent::isRunning() const noexcept {
    return m_running.load(memory_order_relaxed);
}
uint64_t SnmpAgent::getTrapsSent() const noexcept {
    return m_trapsSent.load(memory_order_relaxed);
}
size_t SnmpAgent::getNodeCount() const noexcept {
    lock_guard<mutex> lock(m_metricsMutex);
    return m_metricsCache.size();
}
// namespace IndustrialGateway
}