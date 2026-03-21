// =============================================================================
// MqttClient.h — MQTT Ingestion Layer
// Industrial IoT Gateway Security Platform
// Standard : C++17
//
// Inherits from mosquittopp (the official C++ wrapper for libmosquitto).
// Responsibilities:
//   • Manage the full connection lifecycle to the local Mosquitto broker
//   • Subscribe to the wildcard topic  factory/sensors/+/data  at QoS 1
//   • Receive raw MQTT payloads and forward them — without any parsing —
//     to a registered MessageCallback (owned by DataProcessor)
//   • Handle reconnection transparently using exponential back-off
//   • Provide a clean shutdown path called from main() on SIGINT
//
// Threading model:
//   libmosquittopp drives its own network loop on a dedicated thread via
//   loop_start().  All mosquittopp virtual callbacks (on_connect, on_message,
//   on_disconnect) execute on that internal thread.  The MessageCallback is
//   therefore invoked from the mosquitto loop thread, NOT the main thread.
//   Callers must ensure the callback implementation is thread-safe.
//
//   A std::mutex (m_stateMutex) guards the internal state variables
//   (m_connected, m_shouldRun) so that start() / stop() called from the
//   main thread are safe to call concurrently with the loop thread.
//
// Error handling:
//   • connect() throws std::runtime_error on a hard configuration error
//     (e.g. mosqpp::lib_init() failure).
//   • Transient broker disconnections are handled internally via
//     on_disconnect() → schedule reconnect — no exception is raised.
// =============================================================================

#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

// mosquittopp — C++ wrapper over libmosquitto
// Install: sudo apt install libmosquitto-dev libmosquittopp-dev
#include <mosquittopp.h>

// C++ standard library
#include <string>
#include <functional>   // std::function — type-erased callback
#include <atomic>       // std::atomic<bool> — lock-free state flags
#include <mutex>        // std::mutex, std::lock_guard
#include <thread>       // std::this_thread::sleep_for
#include <chrono>       // std::chrono::seconds
#include <stdexcept>    // std::runtime_error

namespace IndustrialGateway {

// =============================================================================
// MqttClient
//
// Derives from mosqpp::mosquittopp so we can override the virtual callbacks.
// The class is final — it is not designed to be sub-classed further.
//
// Typical usage in main.cpp:
//
//   MqttClient mqtt("iiot_gateway_pi4", "localhost", 1883, 60);
//   mqtt.setMessageCallback([&processor](const std::string& topic,
//                                        const std::string& payload) {
//       processor.onRawMessage(topic, payload);
//   });
//   mqtt.start();          // connects + starts the loop thread
//   // ... run event loop ...
//   mqtt.stop();           // graceful shutdown
// =============================================================================
class MqttClient final : public mosqpp::mosquittopp {
public:

    // -------------------------------------------------------------------------
    // MessageCallback — the type-erased callback signature.
    //
    // Parameters (both are copied into the lambda by the MQTT loop thread):
    //   topic   — full MQTT topic string, e.g. "factory/sensors/ESP32_SEC_01/data"
    //   payload — raw UTF-8 JSON string from the ESP32 message body
    //
    // The callback is invoked once per received message, from the mosquitto
    // loop thread.  The implementation (DataProcessor::onRawMessage) must
    // be thread-safe.
    // -------------------------------------------------------------------------
    using MessageCallback = std::function<void(const std::string& topic,
                                               const std::string& payload)>;

    // -------------------------------------------------------------------------
    // Constructor
    //
    // Initialises the mosquitto library (mosqpp::lib_init()) and stores
    // connection parameters.  Does NOT connect to the broker yet — call
    // start() for that.
    //
    // Parameters:
    //   clientId   — unique MQTT client identifier (max 23 chars per spec)
    //   host       — broker hostname or IP, default "localhost"
    //   port       — broker port, default 1883
    //   keepAlive  — broker keep-alive interval in seconds, default 60
    //   topic      — wildcard subscription topic, default "factory/sensors/+/data"
    //
    // Throws:
    //   std::runtime_error — if mosqpp::lib_init() returns a non-OK code,
    //                        meaning the native mosquitto library is broken.
    // -------------------------------------------------------------------------
    explicit MqttClient(
        const std::string& clientId,
        const std::string& host      = "localhost",
        int                port      = 1883,
        int                keepAlive = 60,
        const std::string& topic     = "factory/sensors/+/data"
    );

    // -------------------------------------------------------------------------
    // Destructor — calls stop() if still running, then mosqpp::lib_cleanup()
    // -------------------------------------------------------------------------
    ~MqttClient() override;

    // Non-copyable / Non-movable: mosquittopp instances own OS sockets
    MqttClient(const MqttClient&)            = delete;
    MqttClient& operator=(const MqttClient&) = delete;
    MqttClient(MqttClient&&)                 = delete;
    MqttClient& operator=(MqttClient&&)      = delete;

    // =========================================================================
    // Public API
    // =========================================================================

    // -------------------------------------------------------------------------
    // setMessageCallback
    //
    // Registers the callback that will be invoked for every received MQTT
    // message.  Must be called BEFORE start().
    //
    // The callback is stored as a std::function, so it accepts lambdas,
    // std::bind expressions, or plain function pointers.
    //
    // Thread safety: safe to call from main thread before start().
    // -------------------------------------------------------------------------
    void setMessageCallback(MessageCallback cb);

    // -------------------------------------------------------------------------
    // start
    //
    // 1. Calls connect_async() to initiate a non-blocking TCP connection
    //    to the broker.
    // 2. Calls loop_start() to spawn the mosquitto network loop on its own
    //    internal thread (handles socket I/O, ping keepalives, QoS retries).
    //
    // Connection completion is confirmed asynchronously via on_connect().
    // If the broker is unavailable, on_disconnect() will fire and reconnect
    // logic will keep retrying with exponential back-off.
    //
    // Throws:
    //   std::runtime_error — on a hard connect_async() failure
    //                        (e.g. invalid hostname format).
    // -------------------------------------------------------------------------
    void start();

    // -------------------------------------------------------------------------
    // stop
    //
    // Signals the loop thread to exit, waits for it to finish (loop_stop()),
    // then disconnects from the broker.  Safe to call multiple times.
    // -------------------------------------------------------------------------
    void stop();

    // -------------------------------------------------------------------------
    // isConnected
    //
    // Returns true if the MQTT session is currently established.
    // Uses std::atomic<bool> — lock-free read, safe from any thread.
    // -------------------------------------------------------------------------
    bool isConnected() const noexcept;

    // -------------------------------------------------------------------------
    // getStats — lightweight diagnostics for the SNMP agent and dashboard
    // -------------------------------------------------------------------------
    uint64_t getTotalMessagesReceived() const noexcept;
    uint64_t getReconnectCount()        const noexcept;

protected:
    // =========================================================================
    // mosquittopp virtual overrides — called from the mosquitto loop thread
    // =========================================================================

    // -------------------------------------------------------------------------
    // on_connect — fired when the TCP+MQTT handshake completes (or fails).
    //
    // rc == 0  → connected successfully → subscribe to the data topic
    // rc != 0  → broker refused connection (bad credentials, ACL, etc.)
    //            → log the reason and let loop_start() handle reconnection
    // -------------------------------------------------------------------------
    void on_connect(int rc) override;

    // -------------------------------------------------------------------------
    // on_disconnect — fired when the connection is lost or gracefully closed.
    //
    // rc == 0  → clean disconnect (stop() was called)
    // rc != 0  → unexpected drop (broker crash, network fault, etc.)
    //            → schedule a reconnect attempt with back-off
    // -------------------------------------------------------------------------
    void on_disconnect(int rc) override;

    // -------------------------------------------------------------------------
    // on_subscribe — fired when the broker confirms a subscription request.
    //
    // Logs the granted QoS level for each filter.  If the broker downgrades
    // QoS (e.g. from 1 to 0 due to ACL), a warning is emitted.
    // -------------------------------------------------------------------------
    void on_subscribe(int mid, int qos_count, const int* granted_qos) override;

    // -------------------------------------------------------------------------
    // on_message — the hot path: called for every incoming MQTT message.
    //
    // Responsibilities here are deliberately minimal:
    //   1. Extract topic string and payload bytes from the mosquitto_message
    //   2. Convert payload to std::string
    //   3. Invoke m_messageCallback (→ DataProcessor::onRawMessage)
    //
    // No JSON parsing, no security checks, no DB writes — those belong in
    // DataProcessor.  Keeping on_message thin prevents the loop thread from
    // being blocked by slow downstream processing.
    // -------------------------------------------------------------------------
    void on_message(const struct mosquitto_message* msg) override;

    // -------------------------------------------------------------------------
    // on_log — forwards mosquitto's internal log messages to our debug log.
    // Only active in DEBUG builds to avoid log spam in production.
    // -------------------------------------------------------------------------
    void on_log(int level, const char* str) override;

private:
    // =========================================================================
    // Private helpers
    // =========================================================================

    // -------------------------------------------------------------------------
    // scheduleReconnect — called from on_disconnect() when rc != 0.
    //
    // Implements a capped exponential back-off:
    //   attempt 1 →  2 s
    //   attempt 2 →  4 s
    //   attempt 3 →  8 s
    //   attempt 4 → 16 s
    //   attempt 5+ → 30 s (cap)
    //
    // Reconnection is attempted by calling reconnect_async() which reuses
    // the existing socket configuration — no need to re-specify host/port.
    // -------------------------------------------------------------------------
    void scheduleReconnect();

    // -------------------------------------------------------------------------
    // mqttRcToString — converts a mosquitto return code to a human-readable
    // string for log messages (avoids magic numbers in log output).
    // -------------------------------------------------------------------------
    static std::string mqttRcToString(int rc);

    // =========================================================================
    // Member variables
    // =========================================================================

    // Connection parameters (set in constructor, read-only thereafter)
    const std::string m_host;
    const int         m_port;
    const int         m_keepAlive;
    const std::string m_topic;
    const int         m_qos = 1;   ///< QoS 1 — "at least once" delivery

    // Subscription QoS requested — must match the const above
    static constexpr int k_subscribeQoS = 1;

    // State flags — std::atomic for lock-free access from multiple threads
    std::atomic<bool>     m_connected;    ///< true while MQTT session is alive
    std::atomic<bool>     m_shouldRun;    ///< false → stop() has been called

    // Reconnection back-off state
    std::mutex            m_reconnMutex;  ///< guards m_reconnectAttempts
    int                   m_reconnectAttempts;  ///< incremented per failed attempt

    // Type-erased callback registered by the DataProcessor
    mutable std::mutex    m_cbMutex;      ///< guards m_messageCallback
    MessageCallback       m_messageCallback;

    // Diagnostics counters — atomic for lock-free reads by SNMP / dashboard
    std::atomic<uint64_t> m_totalMessages;   ///< messages received since start
    std::atomic<uint64_t> m_reconnectCount;  ///< total reconnection attempts
};

} // namespace IndustrialGateway

#endif // MQTT_CLIENT_H