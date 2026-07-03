const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const router = express.Router();

const { parseLogFile } = require('../parser');
const { analyze } = require('../analyzer');
const Log = require('../models/Log');

// сохранение в uploads/
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
        console.log(`Парсим файл: ${req.file.originalname}`);
        const entries = await parseLogFile(req.file.path);

        if (entries.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(422).json({
                error: 'Файл не содержит распознанных записей. Проверь формат (nginx/apache combined log).',
            });
        }

        console.log(`Анализируем ${entries.length} записей...`);
        const analysis = analyze(entries);

        // первые 1000 записей для таблицы
        const log = new Log({
            filename: req.file.originalname,
            ...analysis,
            entries: entries.slice(0, 1000),
        });
        await log.save();
        fs.unlinkSync(req.file.path);

        console.log(`Готово. Аномалий найдено: ${analysis.anomalies.length}`);

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
        console.error('Ошибка анализа:', err);
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

// GET /api/logs/:id/export?format=json|csv|txt
router.get('/:id/export', async (req, res) => {
    try {
        const log = await Log.findById(req.params.id);
        if (!log) return res.status(404).json({ error: 'Лог не найден' });

        const format = (req.query.format || 'json').toLowerCase();
        const baseName = log.filename.replace(/\.[^.]+$/, '');

        if (format === 'json') {
            const payload = {
                filename: log.filename,
                analyzedAt: log.uploadedAt,
                summary: { totalRequests: log.totalRequests, uniqueIPs: log.uniqueIPs, errorCount: log.errorCount, anomaliesCount: log.anomalies.length },
                statusCodes: log.statusCodes,
                anomalies: log.anomalies,
                topIPs: log.topIPs,
                topEndpoints: log.topEndpoints,
                requestsByHour: log.requestsByHour,
            };
            res.setHeader('Content-Disposition', `attachment; filename="${baseName}-report.json"`);
            res.setHeader('Content-Type', 'application/json');
            return res.send(JSON.stringify(payload, null, 2));
        }

        if (format === 'txt') {
            const sep = '='.repeat(60);
            const thin = '-'.repeat(60);
            const date = new Date(log.uploadedAt).toLocaleString('ru');
            let out = '';
            out += `${sep}\n  ОТЧЁТ ОБ АНАЛИЗЕ ЛОГ-ФАЙЛА\n${sep}\n`;
            out += `  Файл:           ${log.filename}\n`;
            out += `  Дата анализа:   ${date}\n${thin}\n\n`;
            out += `СВОДКА\n${thin}\n`;
            out += `  Всего запросов:    ${log.totalRequests.toLocaleString('ru')}\n`;
            out += `  Уникальных IP:     ${log.uniqueIPs.toLocaleString('ru')}\n`;
            out += `  Ошибок 4xx/5xx:    ${log.errorCount.toLocaleString('ru')}\n`;
            out += `  Аномалий:          ${log.anomalies.length}\n\n`;
            out += `СТАТУС-КОДЫ\n${thin}\n`;
            out += `  2xx (успех):       ${log.statusCodes['2xx'].toLocaleString('ru')}\n`;
            out += `  3xx (редирект):    ${log.statusCodes['3xx'].toLocaleString('ru')}\n`;
            out += `  4xx (ошибка кл.):  ${log.statusCodes['4xx'].toLocaleString('ru')}\n`;
            out += `  5xx (ошибка сер.): ${log.statusCodes['5xx'].toLocaleString('ru')}\n\n`;
            if (log.anomalies.length > 0) {
                out += `ОБНАРУЖЕННЫЕ АНОМАЛИИ\n${thin}\n`;
                log.anomalies.forEach((a, i) => {
                    const sev = a.severity === 'critical' ? '[КРИТИЧНО]' : '[ВНИМАНИЕ]';
                    out += `  ${i + 1}. ${sev} ${a.title}\n     ${a.description}\n\n`;
                });
            }
            out += `ТОП IP-АДРЕСОВ\n${thin}\n`;
            log.topIPs.slice(0, 10).forEach(ip => {
                const flag = ip.flag === 'suspicious' ? '! ПОДОЗР.' : ip.flag === 'watch' ? '~ СЛЕДИМ ' : '+ НОРМА  ';
                out += `  ${flag}  ${ip.ip.padEnd(18)} ${String(ip.count).padStart(6)} запр.  ${String(ip.errors||0).padStart(5)} ошибок\n`;
            });
            out += `\nТОП ЭНДПОИНТОВ\n${thin}\n`;
            log.topEndpoints.slice(0, 10).forEach(ep => {
                const rate = ep.count ? Math.round((ep.errorCount / ep.count) * 100) : 0;
                out += `  ${ep.path.padEnd(32)} ${String(ep.count).padStart(6)} запр.  ${String(rate).padStart(3)}% ошибок\n`;
            });
            out += `\n${sep}\n  Сгенерировано: Log Analyzer\n${sep}\n`;
            res.setHeader('Content-Disposition', `attachment; filename="${baseName}-report.txt"`);
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            return res.send(out);
        }

        res.status(400).json({ error: 'Неизвестный формат. Доступны: json, csv, txt' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
module.exports = router;
