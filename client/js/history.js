async function loadHistory() {
  const loading = document.getElementById('loadingState');
  const empty = document.getElementById('emptyState');
  const historyList = document.getElementById('historyList');
  const historyItems = document.getElementById('historyItems');

  try {
    const res = await fetch('/api/logs');
    if (!res.ok) throw new Error('Ошибка загрузки');
    const logs = await res.json();

    loading.classList.add('d-none');

    if (!logs.length) {
      empty.classList.remove('d-none');
      return;
    }

    historyList.classList.remove('d-none');
    historyItems.innerHTML = logs.map(log => {
      const date = new Date(log.uploadedAt).toLocaleString('ru', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
      });
      const anomalyBadge = log.anomaliesCount > 0
          ? `<span class="badge bg-danger">${log.anomaliesCount} аномали${log.anomaliesCount === 1 ? 'я' : 'й'}</span>`
          : `<span class="badge bg-success">Чисто</span>`;

      // Оборачиваем ссылку и кнопку в общий div с data-id
      return `
        <div class="history-card mb-2" data-id="${log.id}">
          <a href="dashboard.html?id=${log.id}" class="list-group-item list-group-item-action history-item border-0 p-3">
            <div class="d-flex align-items-center gap-3">
              <i class="ti ti-file-text fs-4 text-primary flex-shrink-0"></i>
              <div class="flex-grow-1 overflow-hidden">
                <div class="fw-medium text-light text-truncate">${log.filename}</div>
                <div class="small text-secondary mt-1">${date}</div>
              </div>
              <div class="d-flex flex-column align-items-end gap-1 flex-shrink-0">
                ${anomalyBadge}
                <span class="small text-secondary">${log.totalRequests.toLocaleString('ru')} запросов</span>
              </div>
              <i class="ti ti-chevron-right text-secondary"></i>
            </div>
          </a>
          <button class="btn btn-outline-danger btn-sm delete-btn w-100 mt-1">
            <i class="ti ti-trash me-1"></i>Удалить
          </button>
        </div>`;
    }).join('');

    // Вешаем обработчик ПОСЛЕ того как список отрисован
    historyItems.addEventListener('click', async (e) => {
      const btn = e.target.closest('.delete-btn');
      if (!btn) return;
      if (!confirm('Удалить этот анализ?')) return;

      const card = btn.closest('.history-card');
      const id = card.dataset.id;

      try {
        const res = await fetch(`/api/logs/${id}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('Ошибка удаления');
        card.remove();
        if (!document.querySelector('.history-card')) {
          historyList.classList.add('d-none');
          empty.classList.remove('d-none');
        }
      } catch (err) {
        alert('Не удалось удалить: ' + err.message);
      }
    });

  } catch (err) {
    loading.innerHTML = `<p class="text-danger">${err.message}</p>`;
  }
}

loadHistory();