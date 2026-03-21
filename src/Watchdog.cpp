// =============================================================================
// Watchdog.cpp  —  Heartbeat Monitor & Device Offline Detection
// Industrial IoT Gateway Security Platform
// Standard : C++17
// =============================================================================

#include "Watchdog.h"

// C++ standard library
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>      // put_time
#include <stdexcept>    // invalid_argument
#include <fstream>      // ofstream

using namespace std;

namespace IndustrialGateway {

// =============================================================================
// Anonymous namespace — file-scope helpers, not exported
// =============================================================================
namespace {

// -----------------------------------------------------------------------------
// nowStr() — UTC timestamp string for log lines: [2024-05-14 08:30:01 UTC]
// Thread-safe: gmtime_r is POSIX reentrant; ostringstream is stack-local.
// -----------------------------------------------------------------------------
string nowStr() {
    auto now  = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    ostringstream oss;
    oss << "[" << put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << " UTC]";
    return oss.str();
}

// -----------------------------------------------------------------------------
// formatDuration — turns a raw seconds count into a human-readable string.
// Examples:  45   → "45s"
//            90   → "1m 30s"
//            3700 → "1h 1m 40s"
// Used in log messages to make silence durations immediately readable.
// -----------------------------------------------------------------------------
string formatDuration(int64_t seconds) {
    if (seconds < 0) return to_string(seconds) + "s";

    int64_t h = seconds / 3600;
    int64_t m = (seconds % 3600) / 60;
    int64_t s = seconds % 60;

    ostringstream oss;
    if (h > 0) oss << h << "h ";
    if (h > 0 || m > 0) oss << m << "m ";
    oss << s << "s";
    return oss.str();
}

// -----------------------------------------------------------------------------
// statusIsAlreadyOffline — returns true for any status that indicates the
// device is already known to be non-operational.  Used to suppress
// repeat alarm events on subsequent scan cycles.
// -----------------------------------------------------------------------------
bool statusIsAlreadyOffline(DeviceStatus s) {
    return s == DeviceStatus::OFFLINE ||
           s == DeviceStatus::FAULTY;
}

} // anonymous namespace

// =============================================================================
// Constructor & Destructor
// =============================================================================

// -----------------------------------------------------------------------------
// Constructor
//
// Validates injected dependencies and opens the debug log in append mode.
// Does NOT start the background thread — call start() explicitly so that
// main.cpp can control the startup order.
// -----------------------------------------------------------------------------
Watchdog::Watchdog(
    shared_ptr<DataProcessor>   processor,
    shared_ptr<DatabaseManager> db,
    WatchdogConfig                   config)
    : m_processor(move(processor))
    , m_db(move(db))
    , m_config(move(config))
    , m_running(false)
    , m_offlineEventCount(0)
    , m_lastScanTime(0)
{
    if (!m_processor) {
        throw invalid_argument(
            "[Watchdog] DataProcessor pointer must not be nullptr."
        );
    }
    if (!m_db) {
        throw invalid_argument(
            "[Watchdog] DatabaseManager pointer must not be nullptr."
        );
    }

    // Open the debug log in append mode — entries survive gateway restarts.
    m_debugLog.open(m_config.debugLogPath, ios::out | ios::app);
    if (!m_debugLog.is_open()) {
        // Non-fatal: log to stderr and continue — the watchdog can run
        // without the file log (DB events are still recorded).
        cerr << nowStr()
                  << " [Watchdog] WARNING: Cannot open debug log '"
                  << m_config.debugLogPath << "' — file logging disabled.\n";
    }

    cout << nowStr() << " [Watchdog] Initialised.\n"
              << "  Check interval   : " << m_config.checkIntervalSec  << "s\n"
              << "  Offline timeout  : " << m_config.offlineTimeoutSec << "s\n"
              << "  Debug log        : " << m_config.debugLogPath << "\n";
}

// -----------------------------------------------------------------------------
// Destructor — ensures thread is joined before the object is destroyed.
// thread::~thread calls terminate() if the thread is still joinable,
// so we MUST call stop() here as a safety net even if the caller already did.
// -----------------------------------------------------------------------------
Watchdog::~Watchdog() {
    stop();   // Idempotent — safe to call twice
    lock_guard<mutex> lock(m_logMutex);
    if (m_debugLog.is_open()) {
        m_debugLog.close();
    }
}

// =============================================================================
// Lifecycle
// =============================================================================

// -----------------------------------------------------------------------------
// start — spawns the background heartbeat thread
//
// thread is not copyable; m_thread is assigned via move-assignment.
// The lambda captures 'this' by pointer — safe because the Watchdog object
// outlives the thread (stop() in the destructor joins before object dies).
// -----------------------------------------------------------------------------
void Watchdog::start() {
    bool expected = false;
    if (!m_running.compare_exchange_strong(expected, true)) {
        cerr << nowStr()
                  << " [Watchdog] WARNING: start() called but thread is "
                     "already running — ignored.\n";
        return;
    }

    // Spawn the worker thread.  We capture 'this' explicitly; the lambda is
    // the thread's entire entry point — it calls workerLoop() and returns.
    m_thread = thread([this]() {
        workerLoop();
    });

    cout << nowStr()
              << " [Watchdog] Heartbeat thread started."
              << " (interval=" << m_config.checkIntervalSec << "s"
              << " timeout=" << m_config.offlineTimeoutSec << "s)\n";

    logEvent("Watchdog thread started. check_interval=" +
             to_string(m_config.checkIntervalSec) + "s" +
             " offline_timeout=" +
             to_string(m_config.offlineTimeoutSec) + "s");
}

// -----------------------------------------------------------------------------
// stop — signals exit and joins the thread
//
// Why condition_variable?
//   Without it, stop() would have to wait up to checkIntervalSec (5 s) for
//   the thread to wake from sleep.  On a Pi4 that powers down in < 1 s, a
//   5-second hang at shutdown is unacceptable.
//
//   m_cv.notify_all() wakes the wait_for() call in workerLoop() instantly.
//   The thread checks m_running == false and exits cleanly.
// -----------------------------------------------------------------------------
void Watchdog::stop() {
    // Atomically set m_running to false.
    // If it was already false (stop() called twice), nothing to do.
    bool wasRunning = m_running.exchange(false);

    // Always notify — harmless if thread already exited
    {
        lock_guard<mutex> lock(m_cvMutex);
        m_cv.notify_all();
    }

    // Only join if the thread is actually joinable (i.e. start() was called)
    if (wasRunning && m_thread.joinable()) {
        cout << nowStr()
                  << " [Watchdog] Stopping — waiting for thread to exit...\n";
        m_thread.join();
        cout << nowStr() << " [Watchdog] Thread exited cleanly.\n";
        logEvent("Watchdog thread stopped. total_offline_events=" +
                 to_string(m_offlineEventCount.load()));
    }
}

// =============================================================================
// Status
// =============================================================================

bool Watchdog::isRunning() const noexcept {
    return m_running.load(memory_order_relaxed);
}

uint64_t Watchdog::getOfflineEventCount() const noexcept {
    return m_offlineEventCount.load(memory_order_relaxed);
}

int64_t Watchdog::getLastScanTime() const noexcept {
    return m_lastScanTime.load(memory_order_relaxed);
}

// =============================================================================
// Worker Thread
// =============================================================================

// -----------------------------------------------------------------------------
// workerLoop — the background thread's entry function
//
// Structure:
//   while (running) {
//       wait_for(checkIntervalSec)    ← wakes early on stop()
//       if (!running) break
//       try { runScan() } catch { log, continue }
//       update m_lastScanTime
//   }
//
// The condition_variable wait pattern:
//   unique_lock is required by wait_for() (unlike lock_guard).
//   The predicate [this]{ return !m_running; } prevents spurious wakeups from
//   exiting the wait prematurely — if m_running is still true after a spurious
//   wakeup, wait_for() returns to sleeping immediately.
// -----------------------------------------------------------------------------
void Watchdog::workerLoop() {
    logEvent("workerLoop() entered.");
    cout << nowStr() << " [Watchdog] Worker loop running.\n";

    while (m_running.load(memory_order_acquire)) {

        // ── Interruptible sleep ───────────────────────────────────────────────
        // wait_for returns cv_status::timeout on normal expiry,
        // or cv_status::no_timeout if notify_all() was called (stop()).
        {
            unique_lock<mutex> lock(m_cvMutex);
            m_cv.wait_for(
                lock,
                chrono::seconds(m_config.checkIntervalSec),
                // Predicate: return true → stop waiting (stop() was called)
                //            return false → keep waiting (normal operation)
                [this]() { return !m_running.load(memory_order_acquire); }
            );
        }

        // Re-check after waking — stop() may have fired
        if (!m_running.load(memory_order_acquire)) {
            break;
        }

        // ── Execute the scan ──────────────────────────────────────────────────
        try {
            runScan();
        }
        catch (const exception& ex) {
            // Log but DO NOT kill the thread — a single DB error on one scan
            // cycle should not take the watchdog offline permanently.
            cerr << nowStr()
                      << " [Watchdog] Exception in runScan(): "
                      << ex.what() << " — continuing.\n";
            logEvent("runScan() threw: " + string(ex.what()));
        }
        catch (...) {
            cerr << nowStr()
                      << " [Watchdog] Unknown exception in runScan()"
                         " — continuing.\n";
            logEvent("runScan() threw unknown exception.");
        }

        // Record the epoch of this completed scan
        m_lastScanTime.store(nowEpoch(), memory_order_relaxed);
    }

    cout << nowStr() << " [Watchdog] Worker loop exited.\n";
    logEvent("workerLoop() exited.");
}

// -----------------------------------------------------------------------------
// runScan — one heartbeat pass over the entire device cache
//
// This is called from workerLoop() every checkIntervalSec seconds.
//
// Key design decisions:
//
//  1. Snapshot copy of the cache
//     getAllCachedReadings() returns a full unordered_map copy with
//     DataProcessor's internal mutex held only during the copy.  We iterate
//     over this local snapshot without holding any locks, which means:
//       • DataProcessor::onRawMessage() can run concurrently while we scan
//       • We never hold two mutexes at once (deadlock prevention)
//       • The snapshot may be slightly stale by the time we reach entry N,
//         but with only a handful of nodes this lag is < 1 ms
//
//  2. Status filter before timeout check
//     If a node's current cache status is already OFFLINE or FAULTY, we do
//     not re-check its timestamp and do not fire another event.  This is the
//     "repeat-alarm suppression" that prevents one row per scan per dead device.
//
//  3. receivedAt vs timestamp
//     We compare against reading.receivedAt (gateway wall-clock, epoch seconds)
//     NOT reading.timestamp (device-reported, could be wrong/spoofed).
//     If receivedAt == 0 the reading is a placeholder inserted by
//     updateCachedStatus() for a device that was never seen this session —
//     it is skipped (placeholder nodes have no last-seen time to compare).
//
//  4. Transition tracking via m_offlineNodes
//     A node is added to m_offlineNodes when it TRANSITIONS to OFFLINE.
//     On the next scan, if the node appears in m_offlineNodes but its
//     status is no longer OFFLINE (DataProcessor::handleRecovery fired),
//     we remove it from m_offlineNodes so the NEXT silence can be detected.
// -----------------------------------------------------------------------------
void Watchdog::runScan() {
    int64_t now = nowEpoch();

    // ── Step 1: Get a snapshot copy of the entire device cache ───────────────
    // This call acquires DataProcessor's m_cacheMutex for the duration of the
    // copy, then releases it.  We do not hold it while iterating.
    auto snapshot = m_processor->getAllCachedReadings();

    if (snapshot.empty()) {
        logEvent("SCAN: cache empty — no devices registered yet.");
        return;
    }

    int checked  = 0;
    int newOffline = 0;
    int recovered  = 0;

    // ── Step 2: Iterate each device in the snapshot ───────────────────────────
    for (const auto& [nodeId, reading] : snapshot) {
        ++checked;

        // ── 2a: Skip placeholder readings (device never seen this session) ────
        // A receivedAt of 0 means DataProcessor inserted a status-only entry
        // (e.g. from a previous offline event's updateCachedStatus call) but
        // no real packet has arrived this session.  No baseline to compare.
        if (reading.receivedAt == 0) {
            logEvent("SCAN: SKIP node=" + nodeId +
                     " (receivedAt=0, never seen this session)");
            continue;
        }

        // ── 2b: Check m_offlineNodes tracking state ───────────────────────────
        bool alreadyTrackedOffline = false;
        {
            lock_guard<mutex> lock(m_scanMutex);
            alreadyTrackedOffline =
                (m_offlineNodes.count(nodeId) > 0);
        }

        // ── 2c: Check if device has recovered since last scan ─────────────────
        // If we previously marked this node OFFLINE but DataProcessor has since
        // cleared it (via handleRecovery), remove it from our tracking set.
        if (alreadyTrackedOffline && !statusIsAlreadyOffline(reading.status)) {
            {
                lock_guard<mutex> lock(m_scanMutex);
                m_offlineNodes.erase(nodeId);
            }
            ++recovered;
            logEvent("SCAN: RECOVERY-RESET node=" + nodeId +
                     " status=" + deviceStatusToString(reading.status));
            continue;   // This node is back online — nothing more to do
        }

        // ── 2d: Skip nodes already in an offline/faulty state ─────────────────
        // If the status in the snapshot is OFFLINE or FAULTY, a transition
        // event was already fired (either by us, or by DataProcessor on
        // NOT_OPERATING).  Do not generate duplicate events.
        if (statusIsAlreadyOffline(reading.status)) {
            // Ensure our tracking map is consistent
            if (!alreadyTrackedOffline) {
                lock_guard<mutex> lock(m_scanMutex);
                m_offlineNodes[nodeId] = now;
            }
            continue;
        }

        // ── 2e: Compute how long this node has been silent ────────────────────
        int64_t silenceSec = now - reading.receivedAt;

        logEvent("SCAN: CHECK node=" + nodeId +
                 " status="     + deviceStatusToString(reading.status) +
                 " silence="    + formatDuration(silenceSec) +
                 " threshold="  + to_string(m_config.offlineTimeoutSec) + "s");

        // ── 2f: Timeout exceeded → fire offline transition ────────────────────
        if (silenceSec > m_config.offlineTimeoutSec) {

            // ── Action 1: Update cache status to OFFLINE ──────────────────────
            // This makes the SNMP agent return the correct status on the next
            // GET request and prevents DataProcessor from running anomaly
            // detection against a stale "OPERATIONAL" baseline.
            m_processor->updateCachedStatus(nodeId, DeviceStatus::OFFLINE);

            // ── Action 2: Insert CRITICAL system_event into SQLite ────────────
            // Build a rich description that includes all diagnostic fields an
            // operator needs to triage the incident from the events table alone.
            string description =
                "device_offline"
                " | node="        + nodeId +
                " | last_seen="   + formatDuration(silenceSec) + " ago" +
                " | silence_s="   + to_string(silenceSec) +
                " | threshold_s=" + to_string(m_config.offlineTimeoutSec) +
                " | last_msg_id=" + to_string(reading.msgId) +
                " | last_status=" + deviceStatusToString(reading.status) +
                " | last_temp="   + (reading.temperature.has_value()
                                     ? to_string(*reading.temperature) + "°C"
                                     : "N/A") +
                " | last_humi="   + (reading.humidity.has_value()
                                     ? to_string(*reading.humidity) + "%"
                                     : "N/A") +
                " | device_ts="   + to_string(reading.timestamp) +
                " | gateway_ts="  + to_string(now);

            SecurityEvent event;
            event.nodeId      = nodeId;
            event.severity    = "CRITICAL";
            event.description = description;
            event.timestamp   = now;

            bool dbOk = m_db->insertSystemEvent(event);
            if (!dbOk) {
                cerr << nowStr()
                          << " [Watchdog] WARNING: DB write failed for"
                             " device_offline event on node '"
                          << nodeId << "'\n";
            }

            // ── Action 3: Add to offline tracking set ─────────────────────────
            {
                lock_guard<mutex> lock(m_scanMutex);
                m_offlineNodes[nodeId] = now;   // Record when we first detected this
            }

            // ── Action 4: Update diagnostics counter ──────────────────────────
            m_offlineEventCount.fetch_add(1, memory_order_relaxed);
            ++newOffline;

            // ── Action 5: Console + log output ────────────────────────────────
            cerr << nowStr()
                      << " [Watchdog][LEVEL_3] ✗ DEVICE OFFLINE"
                      << " node='"    << nodeId << "'"
                      << " silent="   << formatDuration(silenceSec)
                      << " last_id="  << reading.msgId << "\n";

            logEvent("OFFLINE node=" + nodeId +
                     " silent=" + formatDuration(silenceSec) +
                     " last_msg_id=" + to_string(reading.msgId) +
                     " db_write=" + (dbOk ? "OK" : "FAILED"));
        }
        // ── 2g: Node is alive — log its health status at DEBUG level ──────────
        else {
            int64_t timeUntilTimeout =
                m_config.offlineTimeoutSec - silenceSec;

            logEvent("SCAN: ALIVE node=" + nodeId +
                     " silence=" + formatDuration(silenceSec) +
                     " timeout_in=" + formatDuration(timeUntilTimeout));
        }
    }

    // ── Step 3: Scan summary ──────────────────────────────────────────────────
    string summary =
        "SCAN-DONE"
        " checked="    + to_string(checked) +
        " new_offline=" + to_string(newOffline) +
        " recovered="  + to_string(recovered) +
        " total_offline_events=" +
        to_string(m_offlineEventCount.load());

    logEvent(summary);

    if (newOffline > 0) {
        cout << nowStr()
                  << " [Watchdog] Scan complete:"
                  << " checked="     << checked
                  << " new_offline=" << newOffline
                  << " recovered="   << recovered << "\n";
    }
}

// =============================================================================
// Private helpers
// =============================================================================

// -----------------------------------------------------------------------------
// logEvent — appends one line to system_debug.log under m_logMutex.
// Non-fatal: if the log file is not open, the message is silently discarded.
// The format mirrors the DataProcessor debug log for consistent grep output.
// -----------------------------------------------------------------------------
void Watchdog::logEvent(const string& msg) const {
    lock_guard<mutex> lock(m_logMutex);
    if (m_debugLog.is_open()) {
        m_debugLog << nowStr() << " [Watchdog] " << msg << "\n";
        // No explicit flush — the OS will buffer debug lines.
        // Offline events are also written to the DB (authoritative record),
        // so we do not need every debug line to survive a crash.
    }
}

// -----------------------------------------------------------------------------
// nowEpoch — current wall-clock Unix epoch seconds (int64_t, Y2038-safe)
// -----------------------------------------------------------------------------
int64_t Watchdog::nowEpoch() {
    return static_cast<int64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

} // namespace IndustrialGateway
