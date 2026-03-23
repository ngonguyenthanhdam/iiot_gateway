// =============================================================================
// Watchdog.h  —  Heartbeat Monitor & Device Offline Detection
// Industrial IoT Gateway Security Platform
// Standard : C++17
//
// ── Purpose ───────────────────────────────────────────────────────────────────
// The Watchdog runs as a dedicated background thread that wakes every
// checkIntervalSec seconds (default 5) and scans the DataProcessor device
// cache for nodes that have gone silent.
//
// A node is declared OFFLINE when:
//   now() − reading.receivedAt  >  offlineTimeoutSec  (default 30 s)
//
// receivedAt is the GATEWAY wall-clock stamp applied by DataProcessor when
// the packet was received — not the device-reported timestamp field, which
// could be stale or spoofed.
//
// ── Actions on timeout ────────────────────────────────────────────────────────
//  1. Update the node's status to OFFLINE in the DataProcessor cache
//     (via DataProcessor::updateCachedStatus)
//  2. Insert a CRITICAL system_event into SQLite
//     (via DatabaseManager::insertSystemEvent)
//     severity    : "CRITICAL"
//     description : "device_offline | node=X | last_seen=Ns ago | …"
//  3. Write a line to logs/system_debug.log
//
// ── Repeat-alarm suppression ──────────────────────────────────────────────────
// Once a node is marked OFFLINE its status in the cache is OFFLINE or FAULTY.
// The Watchdog checks the cached status before firing — it will NOT insert a
// duplicate system_event on every scan cycle.  A new event is only logged
// when the node TRANSITIONS from a non-offline state to OFFLINE.
// This prevents the system_events table from being flooded with one row every
// 5 seconds for every dead device.
//
// ── Recovery handoff ──────────────────────────────────────────────────────────
// The Watchdog only marks devices offline.  It never marks them recovered.
// Recovery is the responsibility of DataProcessor::handleRecovery(), which
// fires when the device resumes sending OPERATIONAL packets.
//
// ── Threading model ───────────────────────────────────────────────────────────
//  • The background thread is spawned in start() and joined in stop().
//  • stop() sets m_running = false and notifies m_cv, so the thread wakes
//    immediately instead of waiting for the next sleep interval to expire.
//  • All interactions with DataProcessor and DatabaseManager go through their
//    own internal mutexes — Watchdog holds no lock of its own during those calls.
//
// ── Error policy ──────────────────────────────────────────────────────────────
//  Constructor throws std::invalid_argument if either pointer is nullptr.
//  The worker loop catches all exceptions so a transient DB error cannot
//  kill the Watchdog thread.
// =============================================================================

#ifndef WATCHDOG_H
#define WATCHDOG_H

// Project headers
#include "DataProcessor.h"       // getAllCachedReadings(), updateCachedStatus()
#include "DatabaseManager.h"     // insertSystemEvent()
#include "models/SensorData.h"   // SecurityEvent, DeviceStatus

// C++ standard library
#include <thread>               // std::thread
#include <mutex>                // std::mutex
#include <condition_variable>   // std::condition_variable (interruptible sleep)
#include <atomic>               // std::atomic<bool>
#include <memory>               // std::shared_ptr
#include <string>
#include <unordered_map>        // per-node transition state
#include <chrono>               // std::chrono::seconds
#include <cstdint>              // int64_t, uint64_t
#include <stdexcept>            // std::invalid_argument
#include <fstream>              // std::ofstream (debug log file)

namespace IndustrialGateway {

// =============================================================================
// WatchdogConfig — tuning parameters loaded from gateway_config.json
// =============================================================================
struct WatchdogConfig {
    int64_t checkIntervalSec  = 5;    ///< How often the thread wakes to scan
    int64_t offlineTimeoutSec = 30;   ///< Silence window before OFFLINE declared
    std::string debugLogPath  = "logs/system_debug.log";
};

// =============================================================================
// Watchdog
//
// Typical usage in main.cpp:
//
//   WatchdogConfig cfg;
//   cfg.checkIntervalSec  = 5;
//   cfg.offlineTimeoutSec = 30;
//
//   Watchdog watchdog(dataProcessor, dbManager, cfg);
//   watchdog.start();
//   // … run until SIGINT …
//   watchdog.stop();   // blocks until thread exits cleanly
// =============================================================================
class Watchdog {
public:

    // -------------------------------------------------------------------------
    // Constructor
    //
    // Parameters:
    //   processor — shared reference to the DataProcessor cache
    //   db        — shared reference to the DatabaseManager for event logging
    //   config    — timing and path configuration
    //
    // Throws:
    //   std::invalid_argument — if processor or db is nullptr
    // -------------------------------------------------------------------------
    explicit Watchdog(
        std::shared_ptr<DataProcessor>   processor,
        std::shared_ptr<DatabaseManager> db,
        WatchdogConfig                   config = {}
    );

    // -------------------------------------------------------------------------
    // Destructor — calls stop() to ensure the thread is joined before the
    // object is destroyed (avoids std::terminate on thread destruction).
    // -------------------------------------------------------------------------
    ~Watchdog();

    // Non-copyable / Non-movable: owns a std::thread
    Watchdog(const Watchdog&)            = delete;
    Watchdog& operator=(const Watchdog&) = delete;
    Watchdog(Watchdog&&)                 = delete;
    Watchdog& operator=(Watchdog&&)      = delete;

    // =========================================================================
    // Lifecycle
    // =========================================================================

    // -------------------------------------------------------------------------
    // start
    //
    // Spawns the background heartbeat thread.
    // Safe to call only once; calling start() a second time is a no-op with
    // a warning printed to stderr.
    // -------------------------------------------------------------------------
    void start();

    // -------------------------------------------------------------------------
    // stop
    //
    // Signals the background thread to exit and BLOCKS until it does.
    // Uses m_cv.notify_all() to wake the thread immediately rather than
    // waiting up to checkIntervalSec seconds for the next scan.
    //
    // Idempotent: safe to call multiple times or if start() was never called.
    // -------------------------------------------------------------------------
    void stop();

    // =========================================================================
    // Status
    // =========================================================================

    // -------------------------------------------------------------------------
    // isRunning — returns true if the worker thread is alive.
    // Lock-free atomic read.
    // -------------------------------------------------------------------------
    bool isRunning() const noexcept;

    // -------------------------------------------------------------------------
    // getOfflineEventCount — total number of device_offline events fired
    // since start().  Used by the SNMP agent for the alert_state OID.
    // -------------------------------------------------------------------------
    uint64_t getOfflineEventCount() const noexcept;

    // -------------------------------------------------------------------------
    // getLastScanTime — Unix epoch of the most recent completed scan.
    // Returns 0 if no scan has run yet.
    // -------------------------------------------------------------------------
    int64_t getLastScanTime() const noexcept;

private:
    // =========================================================================
    // Worker thread
    // =========================================================================

    // -------------------------------------------------------------------------
    // workerLoop — the function executed by the background std::thread.
    //
    // Loop body:
    //   1. Sleep for checkIntervalSec using a condition_variable wait_for
    //      (wakes immediately if stop() is called).
    //   2. If m_running is false, exit the loop.
    //   3. Call runScan() to check all known devices.
    //   4. Update m_lastScanTime.
    //   5. Repeat.
    //
    // All exceptions inside runScan() are caught and logged here so that a
    // transient DB error cannot kill the thread permanently.
    // -------------------------------------------------------------------------
    void workerLoop();

    // -------------------------------------------------------------------------
    // runScan — one full heartbeat pass over all cached devices.
    //
    // For each (nodeId, reading) in the DataProcessor cache snapshot:
    //   a) Skip if status is already OFFLINE or FAULTY — transition already fired.
    //   b) Compute silenceSec = now() − reading.receivedAt.
    //   c) If silenceSec > offlineTimeoutSec AND node not already in
    //      m_offlineNodes set:
    //        • Call DataProcessor::updateCachedStatus(OFFLINE)
    //        • Call DatabaseManager::insertSystemEvent() with CRITICAL severity
    //        • Add nodeId to m_offlineNodes (suppresses repeat alarms)
    //        • Increment m_offlineEventCount
    //   d) If silenceSec <= offlineTimeoutSec AND node IS in m_offlineNodes:
    //        • Remove from m_offlineNodes (the device has come back online;
    //          DataProcessor::handleRecovery handles the full recovery flow,
    //          but we reset our tracking state here so the NEXT silence can
    //          be detected fresh).
    // -------------------------------------------------------------------------
    void runScan();

    // =========================================================================
    // Logging helpers
    // =========================================================================

    // -------------------------------------------------------------------------
    // logEvent — writes a line to the debug log file (non-fatal if file absent).
    // -------------------------------------------------------------------------
    void logEvent(const std::string& msg) const;

    // -------------------------------------------------------------------------
    // nowEpoch — current wall-clock Unix epoch seconds.
    // -------------------------------------------------------------------------
    static int64_t nowEpoch();

    // =========================================================================
    // Member variables
    // =========================================================================

    // Injected dependencies (shared ownership)
    std::shared_ptr<DataProcessor>   m_processor;
    std::shared_ptr<DatabaseManager> m_db;

    // Configuration — read-only after construction
    const WatchdogConfig m_config;

    // ── Thread lifecycle ──────────────────────────────────────────────────────
    std::thread              m_thread;    ///< The background heartbeat thread
    std::atomic<bool>        m_running;   ///< true while thread should loop

    // Condition variable used for interruptible sleep.
    // m_cv.wait_for() inside workerLoop() returns early when stop() calls
    // m_cv.notify_all(), avoiding the full checkIntervalSec wait on shutdown.
    mutable std::mutex       m_cvMutex;
    std::condition_variable  m_cv;

    // ── Per-node offline transition tracking ──────────────────────────────────
    // Nodes currently in the OFFLINE state (transition already logged).
    // Stored as a set emulated with unordered_map<string, int64_t> so we can
    // also record when the node first went offline (for future reporting).
    //
    // Protected by m_scanMutex — only accessed from the worker thread, so
    // in practice no contention occurs (the mutex is a safety guard).
    mutable std::mutex                           m_scanMutex;
    std::unordered_map<std::string, int64_t>     m_offlineNodes;
    ///< Key: nodeId, Value: epoch when the offline transition was first detected

    // ── Diagnostics ───────────────────────────────────────────────────────────
    std::atomic<uint64_t> m_offlineEventCount;   ///< total device_offline events
    std::atomic<int64_t>  m_lastScanTime;         ///< epoch of last completed scan

    // ── Debug log file ────────────────────────────────────────────────────────
    mutable std::mutex    m_logMutex;
    mutable std::ofstream m_debugLog;
};

} // namespace IndustrialGateway
#endif // WATCHDOG_H