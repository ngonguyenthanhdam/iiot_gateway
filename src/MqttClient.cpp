// =============================================================================
// MqttClient.cpp — MQTT Ingestion Layer Implementation
// Industrial IoT Gateway Security Platform
// Standard : C++17
// =============================================================================

#include "MqttClient.h"

// C++ standard library
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>     // put_time
#include <algorithm>   // min
#include <cstring>     // strlen

namespace IndustrialGateway {

using namespace std;
using namespace chrono;

// =============================================================================
// Internal helpers (file-scope anonymous namespace — not exported)
// =============================================================================
namespace {

// Using declarations scoped to this anonymous namespace.
using string;
using ostringstream;
using time_t;
using tm;
using put_time;
using min;
using chrono::system_clock;
using seconds;

// -----------------------------------------------------------------------------
// nowStr() — UTC timestamp prefix for every log line, e.g.
//            [2024-05-14 08:30:01 UTC]
// Called from multiple methods; kept as a free function to avoid code dup.
// -----------------------------------------------------------------------------
string nowStr() {
    auto now = system_clock::now();
    time_t t = system_clock::to_time_t(now);
    tm tm_buf{};
    gmtime_r(&t, &tm_buf);   // POSIX thread-safe variant of gmtime()
    ostringstream oss;
    oss << "[" << put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << " UTC]";
    return oss.str();
}

// -----------------------------------------------------------------------------
// backOffSeconds — returns the reconnection delay for a given attempt number.
//
// Strategy: capped binary exponential back-off
//   attempt 0 →  2 s
//   attempt 1 →  4 s
//   attempt 2 →  8 s
//   attempt 3 → 16 s
//   attempt 4+ → 30 s  (cap prevents infinite growth)
//
// Starting at 2 s (not 1 s) gives the broker a reasonable recovery window
// on a Pi4 that may be restarting its own Mosquitto service.
// -----------------------------------------------------------------------------
int backOffSeconds(int attempt) {
    constexpr int kMaxBackOff = 30;
    int delay = 2 << min(attempt, 3);   // 2, 4, 8, 16 → cap at 30
    return min(delay, kMaxBackOff);
}

} // anonymous namespace

// Using declarations for the IndustrialGateway namespace scope.
using string;
using mutex;
using lock_guard;
using thread;
using runtime_error;
using function;
using cout;
using cerr;
using move;
using to_string;
using strlen;
using strerror;
using size_t;
using memory_order_relaxed;
using sleep_for;
using seconds;

// =============================================================================
// Constructor
// =============================================================================

// -----------------------------------------------------------------------------
// MqttClient constructor
//
// mosquittopp(clientId, cleanSession=true):
//   cleanSession=true means the broker discards any queued messages from a
//   previous session for this clientId.  This is correct for a gateway that
//   processes data in real-time — stale queued messages from an offline period
//   would trigger false anomaly-detection alerts.
//
// lib_init() / lib_cleanup() are reference-counted by libmosquitto, so it is
// safe to have multiple MqttClient instances in a process (though the gateway
// currently uses only one).
// -----------------------------------------------------------------------------
MqttClient::MqttClient(
    const string& clientId,
    const string& host,
    int                port,
    int                keepAlive,
    const string& topic)
    : mosqpp::mosquittopp(clientId.c_str(), /*cleanSession=*/true)
    , m_host(host)
    , m_port(port)
    , m_keepAlive(keepAlive)
    , m_topic(topic)
    , m_connected(false)
    , m_shouldRun(false)
    , m_reconnectAttempts(0)
    , m_totalMessages(0)
    , m_reconnectCount(0)
{
    // Initialise the mosquitto C library.
    // mosqpp::lib_init() calls mosquitto_lib_init() internally — it is safe
    // to call multiple times (internally ref-counted).
    int rc = mosqpp::lib_init();
    if (rc != MOSQ_ERR_SUCCESS) {
        throw runtime_error(
            "[MqttClient] mosqpp::lib_init() failed: " + mqttRcToString(rc)
        );
    }

    cout << nowStr()
              << " [MQTT] Library initialised. Client ID: '"
              << clientId << "'\n";
}

// =============================================================================
// Destructor
// =============================================================================

MqttClient::~MqttClient() {
    // Ensure the loop thread and broker connection are cleanly shut down
    // before the object is destroyed.  stop() is idempotent — safe to call
    // even if it was already called by the caller.
    stop();

    // Release the mosquitto library resources.
    // Matches the lib_init() call in the constructor.
    mosqpp::lib_cleanup();

    cout << nowStr() << " [MQTT] Library cleaned up.\n";
}

// =============================================================================
// Public API
// =============================================================================

// -----------------------------------------------------------------------------
// setMessageCallback
//
// The callback is wrapped in a function and stored under m_cbMutex.
// on_message() acquires the same mutex before invoking it, preventing a race
// condition where stop() + setMessageCallback() could run concurrently with
// an incoming message delivery.
// -----------------------------------------------------------------------------
void MqttClient::setMessageCallback(MessageCallback cb) {
    lock_guard<mutex> lock(m_cbMutex);
    m_messageCallback = move(cb);
    cout << nowStr() << " [MQTT] Message callback registered.\n";
}

// -----------------------------------------------------------------------------
// start
//
// Initiates the non-blocking connection and launches the mosquitto I/O thread.
//
// connect_async() vs connect():
//   We use the async variant so that start() returns immediately even if the
//   broker is temporarily unavailable.  on_connect() fires once the TCP
//   handshake completes; on_disconnect() fires if it fails, triggering the
//   reconnect back-off path.
//
// loop_start():
//   Spawns a dedicated POSIX thread inside libmosquitto that:
//     - handles all socket read/write
//     - sends PINGREQ to the broker every keep_alive seconds
//     - retransmits unacknowledged QoS1/2 messages
//   This thread runs until loop_stop() is called.
// -----------------------------------------------------------------------------
void MqttClient::start() {
    m_shouldRun.store(true);

    cout << nowStr()
              << " [MQTT] Connecting to broker at "
              << m_host << ":" << m_port
              << " (keep-alive=" << m_keepAlive << "s)...\n";

    // connect_async() initiates the TCP connection without blocking.
    // The third parameter (bind_address) is nullptr — use the OS default.
    int rc = connect_async(m_host.c_str(), m_port, m_keepAlive);
    if (rc != MOSQ_ERR_SUCCESS) {
        throw runtime_error(
            "[MqttClient] connect_async() failed: " + mqttRcToString(rc) +
            " — broker: " + m_host + ":" + to_string(m_port)
        );
    }

    // Start the mosquitto network I/O thread.
    // After this call, on_connect / on_message / on_disconnect are all
    // driven by the internal loop thread.
    rc = loop_start();
    if (rc != MOSQ_ERR_SUCCESS) {
        // Hard failure — the OS couldn't create the thread
        throw runtime_error(
            "[MqttClient] loop_start() failed: " + mqttRcToString(rc)
        );
    }

    cout << nowStr() << " [MQTT] Network loop thread started.\n";
}

// -----------------------------------------------------------------------------
// stop
//
// Performs a graceful teardown:
//   1. Clear the m_shouldRun flag so on_disconnect() knows this is intentional
//   2. Publish a "gateway offline" notice (best-effort, QoS 0) — optional
//   3. disconnect() sends a MQTT DISCONNECT packet to the broker
//   4. loop_stop(true) joins the mosquitto I/O thread
//
// Idempotent: safe to call if already stopped.
// -----------------------------------------------------------------------------
void MqttClient::stop() {
    // Use exchange to avoid calling stop() twice doing redundant work
    bool wasRunning = m_shouldRun.exchange(false);
    if (!wasRunning) {
        return;   // Already stopped — nothing to do
    }

    cout << nowStr() << " [MQTT] Stopping client...\n";

    // Send a clean MQTT DISCONNECT packet to the broker.
    // This ensures the broker knows we are intentionally leaving (vs a crash),
    // which suppresses the Last Will and Testament message if one was set.
    disconnect();

    // loop_stop(force=true) signals the mosquitto I/O thread to exit and
    // then joins it.  With force=true it won't wait for pending messages —
    // appropriate for a SIGINT shutdown path.
    loop_stop(/*force=*/true);

    m_connected.store(false);
    cout << nowStr() << " [MQTT] Client stopped.\n";
}

// -----------------------------------------------------------------------------
// isConnected — lock-free atomic read
// -----------------------------------------------------------------------------
bool MqttClient::isConnected() const noexcept {
    return m_connected.load(memory_order_relaxed);
}

uint64_t MqttClient::getTotalMessagesReceived() const noexcept {
    return m_totalMessages.load(memory_order_relaxed);
}

uint64_t MqttClient::getReconnectCount() const noexcept {
    return m_reconnectCount.load(memory_order_relaxed);
}

// =============================================================================
// mosquittopp virtual overrides
// (all called from the mosquitto internal loop thread)
// =============================================================================

// -----------------------------------------------------------------------------
// on_connect
//
// rc == 0  → CONNACK: Connection Accepted
// rc == 1  → Refused: unacceptable protocol version
// rc == 2  → Refused: identifier rejected
// rc == 3  → Refused: broker unavailable
// rc == 4  → Refused: bad user name or password
// rc == 5  → Refused: not authorised
//
// On success: subscribe to the sensor data topic at QoS 1.
// On failure: log the refusal code — loop_start() will re-attempt via the
//             automatic reconnect built into libmosquitto.
// -----------------------------------------------------------------------------
void MqttClient::on_connect(int rc) {
    if (rc == MOSQ_ERR_SUCCESS) {
        m_connected.store(true);
        m_reconnectAttempts = 0;   // Reset back-off counter on clean connect

        cout << nowStr()
                  << " [MQTT] ✓ Connected to broker "
                  << m_host << ":" << m_port << "\n";

        // Subscribe to the wildcard topic.
        // The '+' single-level wildcard matches any node_id segment, so one
        // subscription receives data from all ESP32 nodes simultaneously:
        //   factory/sensors/ESP32_SEC_01/data
        //   factory/sensors/ESP32_SEC_02/data   … etc.
        //
        // mid (message ID) is output-only — we log it in on_subscribe().
        int mid = 0;
        int subRc = subscribe(&mid, m_topic.c_str(), k_subscribeQoS);
        if (subRc != MOSQ_ERR_SUCCESS) {
            cerr << nowStr()
                      << " [MQTT] ✗ subscribe() failed: "
                      << mqttRcToString(subRc) << "\n";
        } else {
            cout << nowStr()
                      << " [MQTT] Subscription sent — topic: '"
                      << m_topic << "'  QoS: " << k_subscribeQoS
                      << "  mid: " << mid << "\n";
        }
    } else {
        m_connected.store(false);
        cerr << nowStr()
                  << " [MQTT] ✗ Broker refused connection: "
                  << connackToString(rc) << " (rc=" << rc << ")\n";
    }
}

// -----------------------------------------------------------------------------
// on_disconnect
//
// rc == 0  → intentional disconnect (stop() was called) — do nothing
// rc != 0  → unexpected drop — schedule a reconnect with back-off
// -----------------------------------------------------------------------------
void MqttClient::on_disconnect(int rc) {
    m_connected.store(false);

    if (rc == 0) {
        // Clean shutdown path — stop() called disconnect() deliberately
        cout << nowStr() << " [MQTT] Cleanly disconnected from broker.\n";
        return;
    }

    // Unexpected disconnection — network fault, broker crash, etc.
    cerr << nowStr()
              << " [MQTT] ✗ Unexpected disconnection: "
              << mqttRcToString(rc) << " (rc=" << rc << ")\n";

    // Only reconnect if stop() hasn't been called
    if (m_shouldRun.load()) {
        scheduleReconnect();
    }
}

// -----------------------------------------------------------------------------
// on_subscribe — broker confirmed our SUBSCRIBE request
// -----------------------------------------------------------------------------
void MqttClient::on_subscribe(int mid, int qos_count, const int* granted_qos) {
    cout << nowStr()
              << " [MQTT] ✓ Subscription confirmed (mid=" << mid
              << ", " << qos_count << " filter(s)):\n";

    for (int i = 0; i < qos_count; ++i) {
        cout << "          Filter[" << i << "]: granted QoS = "
                  << granted_qos[i];

        // Warn if broker downgraded QoS (e.g. due to ACL configuration)
        if (granted_qos[i] < k_subscribeQoS) {
            cout << "  ⚠ WARNING: broker downgraded from QoS "
                      << k_subscribeQoS << " to " << granted_qos[i];
        }
        cout << "\n";
    }
}

// -----------------------------------------------------------------------------
// on_message — hot path, called for EVERY received MQTT publish
//
// Design principle: do the minimum necessary here.
//   1. Guard against null / empty payloads
//   2. Copy the raw bytes into a string (O(n) but unavoidable)
//   3. Invoke the registered callback with (topic, payload)
//   4. Increment the diagnostic counter
//
// All business logic (JSON parsing, security checks, DB writes) lives in
// DataProcessor::onRawMessage() which is invoked via the callback.
// This keeps the mosquitto loop thread unblocked between messages.
//
// Note on mosquitto_message ownership:
//   The mosquitto_message* pointer is only valid for the duration of this
//   callback.  libmosquitto frees it immediately after on_message() returns,
//   which is why we copy the payload into a string immediately.
// -----------------------------------------------------------------------------
void MqttClient::on_message(const struct mosquitto_message* msg) {
    // Guard: mosquitto should never pass nullptr, but be defensive
    if (!msg) {
        cerr << nowStr() << " [MQTT] on_message: null message pointer\n";
        return;
    }

    // Guard: ignore retain-flagged messages on reconnect.
    // Retained messages are the broker's cached "last known value" — we
    // don't want them to trigger replay-attack detection by presenting an
    // old msg_id as a new message.
    if (msg->retain) {
        cout << nowStr()
                  << " [MQTT] Ignoring retained message on topic: "
                  << (msg->topic ? msg->topic : "<null>") << "\n";
        return;
    }

    // Extract and validate the topic string
    if (!msg->topic || strlen(msg->topic) == 0) {
        cerr << nowStr() << " [MQTT] on_message: empty topic, discarding\n";
        return;
    }
    const string topic(msg->topic);

    // Extract and validate the payload
    // payloadlen == 0 is a legitimate "null" MQTT message used to clear
    // retained topics — not applicable here, but handled gracefully.
    if (!msg->payload || msg->payloadlen == 0) {
        cerr << nowStr()
                  << " [MQTT] on_message: empty payload on topic '"
                  << topic << "', discarding\n";
        return;
    }

    // Copy raw bytes into a string.
    // msg->payload is void* — cast to char* for the string constructor.
    // payloadlen is the exact byte count (no null terminator guaranteed).
    const string payload(
        static_cast<const char*>(msg->payload),
        static_cast<size_t>(msg->payloadlen)
    );

    // Diagnostic counter — relaxed ordering is fine for a counter
    m_totalMessages.fetch_add(1, memory_order_relaxed);

#ifdef DEBUG
    // Verbose logging in debug builds only — would spam logs in production
    cout << nowStr()
              << " [MQTT] MSG #" << m_totalMessages.load()
              << " topic='" << topic
              << "' len=" << msg->payloadlen
              << " qos=" << msg->qos << "\n";
#endif

    // Forward to DataProcessor via the registered callback.
    // The mutex prevents a race if setMessageCallback() is called while a
    // message is being delivered (extremely unlikely but possible).
    {
        lock_guard<mutex> lock(m_cbMutex);
        if (m_messageCallback) {
            // Invoke the callback — this is the handoff point to DataProcessor.
            // topic and payload are both string copies, so they remain
            // valid after on_message() returns and libmosquitto frees msg.
            m_messageCallback(topic, payload);
        } else {
            cerr << nowStr()
                      << " [MQTT] WARNING: No message callback registered. "
                      << "Call setMessageCallback() before start().\n";
        }
    }
}

// -----------------------------------------------------------------------------
// on_log — forward mosquitto's internal diagnostic messages to stdout.
// Only compiled in DEBUG builds to keep production logs clean.
// -----------------------------------------------------------------------------
void MqttClient::on_log(int level, const char* str) {
#ifdef DEBUG
    // Translate mosquitto log level constants to human-readable prefix
    const char* prefix = "DEBUG";
    if      (level == MOSQ_LOG_INFO)    prefix = "INFO";
    else if (level == MOSQ_LOG_NOTICE)  prefix = "NOTICE";
    else if (level == MOSQ_LOG_WARNING) prefix = "WARNING";
    else if (level == MOSQ_LOG_ERR)     prefix = "ERROR";

    cout << nowStr()
              << " [MOSQ:" << prefix << "] "
              << (str ? str : "<null>") << "\n";
#else
    // Suppress unused parameter warnings in release builds
    (void)level;
    (void)str;
#endif
}

// =============================================================================
// Private helpers
// =============================================================================

// -----------------------------------------------------------------------------
// scheduleReconnect
//
// Called from on_disconnect() when an unexpected drop is detected and
// m_shouldRun is still true.
//
// We sleep on a temporary thread rather than blocking the mosquitto
// loop thread.  After the back-off delay, reconnect_async() reuses the
// existing connection parameters stored in the mosquittopp base object.
//
// The reconnect thread is detached — it will complete its sleep and either
// successfully reconnect (triggering on_connect again) or be abandoned when
// the process exits.
// -----------------------------------------------------------------------------
void MqttClient::scheduleReconnect() {
    int attempt;
    {
        lock_guard<mutex> lock(m_reconnMutex);
        attempt = m_reconnectAttempts++;
    }

    m_reconnectCount.fetch_add(1, memory_order_relaxed);

    int delaySec = backOffSeconds(attempt);

    cout << nowStr()
              << " [MQTT] Reconnect attempt #" << (attempt + 1)
              << " scheduled in " << delaySec << "s...\n";

    // Detach a short-lived thread that sleeps, then reconnects.
    // Using thread here is deliberate — we must NOT sleep on the
    // mosquitto loop thread itself (that would stall QoS retransmissions
    // and keep-alive pings for other potential clients on the same broker).
    thread([this, delaySec]() {
        sleep_for(seconds(delaySec));

        // Check again after waking: stop() may have been called during sleep
        if (!m_shouldRun.load()) {
            cout << nowStr()
                      << " [MQTT] Reconnect cancelled (stop() was called).\n";
            return;
        }

        cout << nowStr() << " [MQTT] Attempting reconnect...\n";

        // reconnect_async() reuses host/port/clientId stored in the
        // mosquittopp base class — no need to re-specify them.
        int rc = reconnect_async();
        if (rc != MOSQ_ERR_SUCCESS) {
            cerr << nowStr()
                      << " [MQTT] reconnect_async() failed: "
                      << mqttRcToString(rc)
                      << " — will retry after next on_disconnect\n";
            // libmosquitto will fire on_disconnect() again, which will
            // call scheduleReconnect() again — the loop continues.
        }
    }).detach();
}

// -----------------------------------------------------------------------------
// connackToString — decodes the rc value passed to on_connect().
//
// The MQTT 3.1.1 CONNACK return codes (0–5) are a completely separate
// namespace from the MOSQ_ERR_* library error codes.  The CONNACK codes are
// ONLY ever delivered via on_connect(rc); they are NEVER returned by library
// calls such as connect_async(), subscribe(), etc.
//
// This function is intentionally separate from mqttRcToString() to avoid the
// duplicate-case-value compiler error that would result from the integer
// overlap: MOSQ_ERR_NOMEM=1, MOSQ_ERR_PROTOCOL=2, … MOSQ_ERR_CONN_REFUSED=5
// all share their numeric values with CONNACK codes 1–5.
// -----------------------------------------------------------------------------
static string connackToString(int rc) {
    switch (rc) {
        case 0: return "Connection accepted";
        case 1: return "CONNACK: Unacceptable protocol version";
        case 2: return "CONNACK: Client identifier rejected";
        case 3: return "CONNACK: Broker unavailable";
        case 4: return "CONNACK: Bad username or password";
        case 5: return "CONNACK: Not authorised";
        default: return "CONNACK: Unknown refusal code (" + to_string(rc) + ")";
    }
}

// -----------------------------------------------------------------------------
// mqttRcToString — decodes MOSQ_ERR_* library return codes only.
//
// Do NOT pass on_connect() rc values here — use connackToString() instead.
// The MQTT CONNACK codes 1–5 collide numerically with MOSQ_ERR_NOMEM(1)
// through MOSQ_ERR_CONN_REFUSED(5), so they are handled in a separate function.
// -----------------------------------------------------------------------------
string MqttClient::mqttRcToString(int rc) {
    switch (rc) {
        case MOSQ_ERR_SUCCESS:       return "Success";
        case MOSQ_ERR_NOMEM:         return "Out of memory";
        case MOSQ_ERR_PROTOCOL:      return "Protocol error";
        case MOSQ_ERR_INVAL:         return "Invalid parameters";
        case MOSQ_ERR_NO_CONN:       return "No connection";
        case MOSQ_ERR_CONN_REFUSED:  return "Connection refused by broker";
        case MOSQ_ERR_NOT_FOUND:     return "Not found";
        case MOSQ_ERR_CONN_LOST:     return "Connection lost";
        case MOSQ_ERR_TLS:           return "TLS error";
        case MOSQ_ERR_PAYLOAD_SIZE:  return "Payload too large";
        case MOSQ_ERR_NOT_SUPPORTED: return "Not supported";
        case MOSQ_ERR_AUTH:          return "Authentication failed";
        case MOSQ_ERR_ACL_DENIED:    return "ACL denied";
        case MOSQ_ERR_UNKNOWN:       return "Unknown error";
        case MOSQ_ERR_ERRNO:         return string("System error: ")
                                          + strerror(errno);
        default: return "Unknown code (" + to_string(rc) + ")";
    }
}
// namespace IndustrialGateway
} 
