// id из url
const params = new URLSearchParams(window.location.search);
const logId = params.get('id');

if (!logId) window.location.href = 'index.html';

// элементы
const loadingState = document.getElementById('loadingState');
const content = document.getElementById('content');

let allEntries = [];
let filteredEntries = [];
let currentPage = 1;
const PAGE_SIZE = 50;

// загрузка данных
async function loadData() {
  try {
    const res = await fetch(`/api/logs/${logId}`);
    if (!res.ok) throw new Error('Не удалось загрузить данные');
    const data = await res.json();

    loadingState.classList.add('d-none');
    content.classList.remove('d-none');

    renderAll(data);
  } catch (err) {
    loadingState.innerHTML = `
      <i class="ti ti-alert-circle fs-1 text-danger mb-3 d-block"></i>
      <p class="text-danger">${err.message}</p>
      <a href="index.html" class="btn btn-outline-secondary btn-sm mt-2">На главную</a>
    `;
  }
}

function renderAll(data) {
  // навбар
  const navFilename = document.getElementById('navFilename');
  navFilename.textContent = data.filename;
  navFilename.classList.remove('d-none');
  document.title = `${data.filename} — Log Analyzer`;

  // карточки статистики
  document.getElementById('statTotal').textContent = data.totalRequests.toLocaleString('ru');
  document.getElementById('statIPs').textContent = data.uniqueIPs.toLocaleString('ru');
  document.getElementById('statErrors').textContent = data.errorCount.toLocaleString('ru');
  document.getElementById('statAnomalies').textContent = data.anomalies.length;

  // аномалии
  if (data.anomalies.length > 0) {
    const badge = document.getElementById('anomalyBadge');
    badge.textContent = data.anomalies.length;
    badge.classList.remove('d-none');
  }

  renderHoursChart(data.requestsByHour);
  renderStatusChart(data.statusCodes);
  renderEndpoints(data.topEndpoints);
  renderAnomalies(data.anomalies);
  renderIPs(data.topIPs);

  allEntries = data.entries || [];
  filteredEntries = allEntries;
  renderEntries();
}

// график по часам
function renderHoursChart(hourData) {
  const counts = hourData.map(h => h.count);
  const avg = counts.reduce((a, b) => a + b, 0) / counts.length;
  const max = Math.max(...counts);

  // час-пик
  if (max > avg * 4) document.getElementById('peakBadge').classList.remove('d-none');

  const backgroundColors = counts.map(c =>
      c === max && c > avg * 4
          ? 'rgba(239, 68, 68, 0.7)'
          : 'rgba(59, 130, 246, 0.6)'
  );
  const borderColors = counts.map(c =>
      c === max && c > avg * 4 ? '#ef4444' : '#3b82f6'
  );

  new Chart(document.getElementById('chartHours'), {
    type: 'bar',
    data: {
      labels: hourData.map(h => `${String(h.hour).padStart(2, '0')}:00`),
      datasets: [{
        data: counts,
        backgroundColor: backgroundColors,
        borderColor: borderColors,
        borderWidth: 1,
        borderRadius: 3,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { color: '#1f2937' } },
        y: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { color: '#1f2937' } },
      },
    },
  });
}

// диаграмма статусов
function renderStatusChart(statusCodes) {
  const data = [statusCodes['2xx'], statusCodes['3xx'], statusCodes['4xx'], statusCodes['5xx']];
  new Chart(document.getElementById('chartStatus'), {
    type: 'doughnut',
    data: {
      labels: ['2xx', '3xx', '4xx', '5xx'],
      datasets: [{
        data,
        backgroundColor: ['#3b82f6', '#f59e0b', '#ef4444', '#7f1d1d'],
        borderWidth: 0,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#9ca3af', font: { size: 12 }, padding: 12 },
        },
      },
    },
  });
}

// топ эндпоинтов
function renderEndpoints(endpoints) {
  const tbody = document.getElementById('endpointsTable');
  tbody.innerHTML = endpoints.slice(0, 15).map(ep => {
    const errRate = ep.count ? Math.round((ep.errorCount / ep.count) * 100) : 0;
    const errClass = errRate >= 90 ? 'text-danger' : errRate >= 50 ? 'text-warning' : 'text-secondary';
    return `
      <tr>
        <td class="font-monospace small text-truncate" style="max-width:300px">${ep.path}</td>
        <td class="text-end">${ep.count.toLocaleString('ru')}</td>
        <td class="text-end ${ep.errorCount > 0 ? 'text-danger' : 'text-secondary'}">${ep.errorCount.toLocaleString('ru')}</td>
        <td class="text-end ${errClass}">${errRate}%</td>
      </tr>`;
  }).join('');
}

// ещё аномалии
function renderAnomalies(anomalies) {
  const list = document.getElementById('anomaliesList');
  const empty = document.getElementById('noAnomalies');

  if (!anomalies.length) {
    empty.classList.remove('d-none');
    return;
  }

  const icons = {
    traffic_spike: 'ti-flame',
    bruteforce: 'ti-lock',
    scan: 'ti-eye',
    server_error: 'ti-server-off',
  };

  list.innerHTML = anomalies.map(a => `
    <div class="card bg-dark-subtle border-secondary mb-3 anomaly-card ${a.severity}">
      <div class="card-body d-flex gap-3">
        <div class="flex-shrink-0 pt-1">
          <i class="ti ${icons[a.type] || 'ti-alert-triangle'} fs-4 ${a.severity === 'critical' ? 'text-danger' : 'text-warning'}"></i>
        </div>
        <div>
          <div class="fw-medium mb-1">${a.title}</div>
          <div class="text-secondary small">${a.description}</div>
        </div>
        <div class="ms-auto">
          <span class="badge ${a.severity === 'critical' ? 'bg-danger' : 'bg-warning text-dark'}">
            ${a.severity === 'critical' ? 'Критично' : 'Внимание'}
          </span>
        </div>
      </div>
    </div>
  `).join('');
}

// таблица ip
function renderIPs(ips) {
  const tbody = document.getElementById('ipsTable');
  tbody.innerHTML = ips.map(ip => {
    const flagLabel = ip.flag === 'suspicious' ? 'Подозрительный' : ip.flag === 'watch' ? 'Следим' : 'Норма';
    const flagClass = ip.flag === 'suspicious' ? 'flag-suspicious' : ip.flag === 'watch' ? 'flag-watch' : 'flag-normal';
    return `
      <tr>
        <td class="font-monospace">${ip.ip}</td>
        <td class="text-end">${ip.count.toLocaleString('ru')}</td>
        <td class="text-end ${ip.errors > 0 ? 'text-danger' : 'text-secondary'}">${(ip.errors || 0).toLocaleString('ru')}</td>
        <td><span class="${flagClass}">● ${flagLabel}</span></td>
      </tr>`;
  }).join('');
}

// записи
function renderEntries() {
  const tbody = document.getElementById('entriesTable');
  const start = (currentPage - 1) * PAGE_SIZE;
  const page = filteredEntries.slice(start, start + PAGE_SIZE);

  tbody.innerHTML = page.map(e => {
    const statusClass = e.status >= 500 ? 'text-danger' : e.status >= 400 ? 'text-warning' : e.status >= 300 ? 'text-info' : 'text-success';
    const time = new Date(e.timestamp).toLocaleTimeString('ru');
    return `
      <tr>
        <td class="text-secondary">${time}</td>
        <td>${e.ip}</td>
        <td><span class="badge bg-secondary">${e.method}</span></td>
        <td class="text-truncate" style="max-width:260px">${e.path}</td>
        <td class="${statusClass} fw-medium">${e.status}</td>
      </tr>`;
  }).join('');

  const total = filteredEntries.length;
  const totalPages = Math.ceil(total / PAGE_SIZE);
  document.getElementById('pageInfo').textContent = `Стр. ${currentPage} из ${totalPages} · ${total.toLocaleString('ru')} записей`;
  document.getElementById('prevPage').disabled = currentPage <= 1;
  document.getElementById('nextPage').disabled = currentPage >= totalPages;
  document.getElementById('entriesCount').textContent = `${total.toLocaleString('ru')} записей`;
}

// поиск фильтры
document.getElementById('searchInput').addEventListener('input', applyFilters);
document.getElementById('statusFilter').addEventListener('change', applyFilters);

function applyFilters() {
  const q = document.getElementById('searchInput').value.toLowerCase();
  const statusPrefix = document.getElementById('statusFilter').value;
  currentPage = 1;

  filteredEntries = allEntries.filter(e => {
    const matchSearch = !q || e.ip.includes(q) || e.path.toLowerCase().includes(q);
    const matchStatus = !statusPrefix || String(e.status).startsWith(statusPrefix);
    return matchSearch && matchStatus;
  });

  renderEntries();
}

document.getElementById('prevPage').addEventListener('click', () => { currentPage--; renderEntries(); });
document.getElementById('nextPage').addEventListener('click', () => { currentPage++; renderEntries(); });

// вкладки
document.querySelectorAll('[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-tab]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    const tab = btn.dataset.tab;
    ['overview', 'anomalies', 'ips', 'entries'].forEach(t => {
      document.getElementById(`tab-${t}`).classList.toggle('d-none', t !== tab);
    });
  });
});

loadData();

// экспорт
document.addEventListener('click', (e) => {
  const btn = e.target.closest('.export-btn');
  if (!btn) return;
  e.preventDefault();
  if (!logId) return;
  const format = btn.dataset.format;
  window.location.href = `/api/logs/${logId}/export?format=${format}`;
});
