const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const router = express.Router();

const { parseLogFile } = require('../parser');
const { analyze } = require('../analyzer');
const Log = require('../models/Log');

// Настройка multer — сохраняем файлы в папку uploads/
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, '../../uploads');
        if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const unique = `${Date.now()}-${file.originalname}`;
        cb(null, unique);
    },
});

const upload = multer({
    storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // максимум 100 МБ
    fileFilter: (req, file, cb) => {
        const allowed = ['.log', '.txt', '.gz'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext) || file.mimetype === 'text/plain') {
            cb(null, true);
        } else {
            cb(new Error('Разрешены только .log, .txt и .gz файлы'));
        }
    },
});

// POST /api/logs/upload — загрузка и анализ файла
router.post('/upload', upload.single('logfile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Файл не загружен' });
    }

    try {
        console.log(`📂 Парсим файл: ${req.file.originalname}`);
        const entries = await parseLogFile(req.file.path);

        if (entries.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(422).json({
                error: 'Файл не содержит распознанных записей. Проверь формат (nginx/apache combined log).',
            });
        }

        console.log(`🔍 Анализируем ${entries.length} записей...`);
        const analysis = analyze(entries);

        // Сохраняем в Mongo (первые 1000 сырых записей для таблицы)
        const log = new Log({
            filename: req.file.originalname,
            ...analysis,
            entries: entries.slice(0, 1000),
        });
        await log.save();

        // Удаляем временный файл
        fs.unlinkSync(req.file.path);

        console.log(`✅ Готово. Аномалий найдено: ${analysis.anomalies.length}`);

        res.json({
            id: log._id,
            filename: log.filename,
            uploadedAt: log.uploadedAt,
            totalRequests: log.totalRequests,
            uniqueIPs: log.uniqueIPs,
            errorCount: log.errorCount,
            anomaliesCount: log.anomalies.length,
        });
    } catch (err) {
        console.error('❌ Ошибка анализа:', err);
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({ error: 'Ошибка при обработке файла: ' + err.message });
    }
});

// GET /api/logs — список всех загруженных логов
router.get('/', async (req, res) => {
    try {
        const logs = await Log.find({}, 'filename uploadedAt totalRequests uniqueIPs errorCount anomalies')
            .sort({ uploadedAt: -1 })
            .limit(20);
        res.json(logs.map(l => ({
            id: l._id,
            filename: l.filename,
            uploadedAt: l.uploadedAt,
            totalRequests: l.totalRequests,
            uniqueIPs: l.uniqueIPs,
            errorCount: l.errorCount,
            anomaliesCount: l.anomalies.length,
        })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/logs/:id — полный результат анализа конкретного лога
router.get('/:id', async (req, res) => {
    try {
        const log = await Log.findById(req.params.id);
        if (!log) return res.status(404).json({ error: 'Лог не найден' });
        res.json(log);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/logs/:id — удаление записи
router.delete('/:id', async (req, res) => {
    try {
        await Log.findByIdAndDelete(req.params.id);
        res.json({ message: 'Удалено' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;