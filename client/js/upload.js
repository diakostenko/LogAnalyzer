const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const clearFile = document.getElementById('clearFile');
const uploadBtn = document.getElementById('uploadBtn');
const progressWrap = document.getElementById('progressWrap');
const progressBar = document.getElementById('progressBar');
const progressLabel = document.getElementById('progressLabel');
const progressPct = document.getElementById('progressPct');
const errorAlert = document.getElementById('errorAlert');
const errorText = document.getElementById('errorText');

let selectedFile = null;

// диалог при клике на зону
dropZone.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

// дрэг эн дроп
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});

// сброс файла
clearFile.addEventListener('click', (e) => {
  e.stopPropagation();
  resetFile();
});

function setFile(file) {
  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  fileInfo.classList.remove('d-none');
  uploadBtn.removeAttribute('disabled');
  hideError();
}

function resetFile() {
  selectedFile = null;
  fileInput.value = '';
  fileInfo.classList.add('d-none');
  uploadBtn.setAttribute('disabled', '');
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function showError(msg) {
  errorText.textContent = msg;
  errorAlert.classList.remove('d-none');
}

function hideError() {
  errorAlert.classList.add('d-none');
}

// загрузка файла
uploadBtn.addEventListener('click', async () => {
  if (!selectedFile) return;

  hideError();
  uploadBtn.setAttribute('disabled', '');
  progressWrap.classList.remove('d-none');

  const formData = new FormData();
  formData.append('logfile', selectedFile);

  try {
    // имитация прогресса
    let fakeProgress = 0;
    const fakeInterval = setInterval(() => {
      if (fakeProgress < 80) {
        fakeProgress += Math.random() * 10;
        setProgress(Math.min(fakeProgress, 80), 'Загрузка файла...');
      }
    }, 200);

    const response = await fetch('/api/logs/upload', {
      method: 'POST',
      body: formData,
    });

    clearInterval(fakeInterval);

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || 'Ошибка сервера');
    }

    setProgress(90, 'Анализируем данные...');
    const data = await response.json();
    setProgress(100, 'Готово!');

    // пауза
    await new Promise(r => setTimeout(r, 400));

    // переход на дашборд
    window.location.href = `dashboard.html?id=${data.id}`;

  } catch (err) {
    progressWrap.classList.add('d-none');
    uploadBtn.removeAttribute('disabled');
    showError(err.message);
  }
});

function setProgress(pct, label) {
  const rounded = Math.round(pct);
  progressBar.style.width = rounded + '%';
  progressPct.textContent = rounded + '%';
  progressLabel.textContent = label;
}
