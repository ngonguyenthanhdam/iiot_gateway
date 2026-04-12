(function () {
  const NODE_ID = 'ESP32_SEC_01';
  const POLL_MS = 10000;
  const OFFLINE_MS = 60000;

  let lastUpdateEpoch = 0;
  let pollTimer = null;
  let eventSource = null;
  let commandPending = false;

  function $(id) {
    return document.getElementById(id);
  }

  function safeText(id, value) {
    const el = $(id);
    if (el) el.textContent = value ?? '--';
  }

  function setBadgeState(state) {
    const badge = $('doorStateBadge');
    if (!badge) return;

    badge.className = 'door-state-badge';
    const s = (state || 'UNKNOWN').toUpperCase();

    if (s === 'LOCKED' || s === 'READY') badge.classList.add('door-state-ready');
    else if (s === 'UNLOCKED' || s === 'OPEN') badge.classList.add('door-state-unlocked');
    else if (s === 'FAULT') badge.classList.add('door-state-fault');
    else if (s === 'OFFLINE') badge.classList.add('door-state-offline');
    else badge.classList.add('door-state-unknown');

    badge.textContent = s;
  }

  function setOfflineState(message) {
    setBadgeState('OFFLINE');
    showCriticalBanner(message || 'Node_01 door status offline (>60s without updates).');
    const clearBtn = $('btnDoorClearFault');
    if (clearBtn) clearBtn.disabled = true;
  }

  function clearCriticalBanner() {
    const box = $('doorCriticalBanner');
    if (!box) return;
    box.classList.add('d-none');
    box.innerHTML = '';
  }

  function showCriticalBanner(message) {
    const box = $('doorCriticalBanner');
    if (!box) return;
    box.classList.remove('d-none');
    box.innerHTML = `<i class="fas fa-triangle-exclamation me-2"></i>${message}`;
  }

  function applyAdminUi() {
    const isAdmin = (window.IS_ADMIN === true || window.IS_ADMIN === 'true');
    const adminBtns = ['btnDoorLock', 'btnDoorUnlock', 'btnDoorClearFault'];
    adminBtns.forEach((id) => {
      const el = $(id);
      if (el) el.classList.toggle('d-none', !isAdmin);
    });

    const msg = $('doorAdminRequiredMsg');
    if (msg) msg.classList.toggle('d-none', isAdmin);
  }

  async function fetchJson(url, options) {
    const res = await fetch(url, options);
    let body = {};
    try { body = await res.json(); } catch (_) {}
    if (!res.ok) {
      const errMsg = body?.error || `${res.status} ${res.statusText}`;
      throw new Error(errMsg);
    }
    return body;
  }

  function updateFaultArea(payload) {
    const faultWrap = $('doorFaultWrap');
    const clearBtn = $('btnDoorClearFault');
    if (!faultWrap || !clearBtn) return;

    if (payload.fault_state) {
      faultWrap.classList.remove('d-none');
      clearBtn.disabled = commandPending ? true : false;
    } else {
      faultWrap.classList.add('d-none');
    }
  }

  function updateAlarmArea(payload) {
    const alarm = $('doorAlarmState');
    if (!alarm) return;
    alarm.textContent = payload.alarm_active ? 'ACTIVE' : 'INACTIVE';
    alarm.className = payload.alarm_active ? 'badge bg-danger' : 'badge bg-secondary';
  }

  function parseGatewayTsToEpoch(ts) {
    if (!ts) return 0;
    const d = new Date(ts);
    if (isNaN(d.getTime())) return 0;
    return d.getTime();
  }

  function renderStatus(payload) {
    const doorState = payload?.door_state || 'UNKNOWN';
    setBadgeState(doorState);

    safeText('doorLastTrigger', payload?.last_trigger || '--');
    safeText('doorLastUid', payload?.last_uid || '--');
    safeText('doorLastGatewayTs', payload?.gateway_received_ts || '--');

    updateFaultArea(payload);
    updateAlarmArea(payload);

    const gatewayEpoch = parseGatewayTsToEpoch(payload?.gateway_received_ts);
    const deviceEpoch = payload?.last_update_ms || 0;
    lastUpdateEpoch = Math.max(gatewayEpoch, deviceEpoch);
    clearCriticalBanner();
  }

  async function refreshDoorStatus() {
    try {
      const payload = await fetchJson(`/api/node/${NODE_ID}/door/status`);
      renderStatus(payload);
    } catch (err) {
      showCriticalBanner(`Door status error: ${err.message}`);
    }
  }

  async function runCommand(action) {
    if (commandPending) return;
    commandPending = true;
    setButtonsDisabled(true);

    try {
      await fetchJson(`/api/node/${NODE_ID}/door/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action })
      });
      await refreshDoorStatus();
      await loadDoorHistory();
    } catch (err) {
      if (String(err.message).toLowerCase().includes('forbidden')) {
        showCriticalBanner('Admin access required for door control.');
      } else {
        showCriticalBanner(`Door command failed: ${err.message}`);
      }
    } finally {
      commandPending = false;
      setButtonsDisabled(false);
    }
  }

  async function clearFault() {
    if (commandPending) return;
    commandPending = true;
    setButtonsDisabled(true);

    try {
      await fetchJson(`/api/node/${NODE_ID}/door/clear_fault`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      await refreshDoorStatus();
      await loadDoorHistory();
    } catch (err) {
      if (String(err.message).toLowerCase().includes('forbidden')) {
        showCriticalBanner('Admin access required to clear fault.');
      } else {
        showCriticalBanner(`Clear fault failed: ${err.message}`);
      }
    } finally {
      commandPending = false;
      setButtonsDisabled(false);
    }
  }

  function setButtonsDisabled(disabled) {
    ['btnDoorLock', 'btnDoorUnlock', 'btnDoorHistory', 'btnDoorRefresh', 'btnDoorClearFault'].forEach((id) => {
      const btn = $(id);
      if (btn) btn.disabled = !!disabled;
    });
  }

  function fmtTs(row) {
    return row.gateway_received_ts || (row.timestamp_ms ? new Date(row.timestamp_ms).toISOString() : '--');
  }

  async function loadDoorHistory() {
    try {
      const rows = await fetchJson(`/api/node/${NODE_ID}/door/history?limit=20`);
      const tbody = $('doorHistoryBody');
      if (!tbody) return;

      tbody.innerHTML = '';
      rows.forEach((r) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${fmtTs(r)}</td>
          <td>${r.event_code || r.event_type || '--'}</td>
          <td>${r.event_type || '--'}</td>
          <td>${extractUid(r.description || '')}</td>
          <td>${r.severity || '--'}</td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      showCriticalBanner(`History load failed: ${err.message}`);
    }
  }

  function extractUid(text) {
    const m = String(text).match(/UID[:=\s]+([A-Za-z0-9_-]+)/i);
    return m ? m[1] : '--';
  }

  function setupSse() {
    if (!window.EventSource) return;
    eventSource = new EventSource('/api/door/alerts/stream');

    eventSource.addEventListener('door_alert', (ev) => {
      try {
        const data = JSON.parse(ev.data || '{}');
        if ((data.severity || '').toUpperCase() === 'CRITICAL') {
          showCriticalBanner(`CRITICAL: ${data.description || data.event_code || 'Door fault detected'}`);
        }
        refreshDoorStatus();
        loadDoorHistory();
      } catch (_) {}
    });

    eventSource.onerror = () => {
      showCriticalBanner('Real-time alert stream disconnected. Using polling fallback.');
    };
  }

  function setupEvents() {
    const lockBtn = $('btnDoorLock');
    const unlockBtn = $('btnDoorUnlock');
    const clearBtn = $('btnDoorClearFault');
    const refreshBtn = $('btnDoorRefresh');
    const historyBtn = $('btnDoorHistory');

    if (lockBtn) lockBtn.addEventListener('click', () => runCommand('lock'));
    if (unlockBtn) unlockBtn.addEventListener('click', () => runCommand('unlock'));
    if (clearBtn) clearBtn.addEventListener('click', () => clearFault());
    if (refreshBtn) refreshBtn.addEventListener('click', async () => {
      await refreshDoorStatus();
      await loadDoorHistory();
    });
    if (historyBtn) historyBtn.addEventListener('click', async () => {
      await loadDoorHistory();
    });
  }

  function setupOfflineWatchdog() {
    setInterval(() => {
      if (!lastUpdateEpoch) return;
      if ((Date.now() - lastUpdateEpoch) > OFFLINE_MS) {
        setOfflineState('No door updates received in last 60s.');
      }
    }, 5000);
  }

  async function init() {
    applyAdminUi();
    setupEvents();
    setupSse();
    setupOfflineWatchdog();
    await refreshDoorStatus();
    await loadDoorHistory();

    pollTimer = setInterval(async () => {
      await refreshDoorStatus();
    }, POLL_MS);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
