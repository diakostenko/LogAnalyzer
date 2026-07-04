const mongoose = require('mongoose');

// Схема одной записи лога (для хранения сырых строк)
const rawEntrySchema = new mongoose.Schema({
    ip: String,
    timestamp: Date,
    method: String,
    path: String,
    status: Number,
    size: Number,
}, { _id: false });

// Схема аномалии
const anomalySchema = new mongoose.Schema({
    type: String,           // 'traffic_spike' | 'bruteforce' | 'scan' | 'server_error'
    severity: String,       // 'critical' | 'warning'
    title: String,
    description: String,
}, { _id: false });

// Основная схема результата анализа
const logSchema = new mongoose.Schema({
    filename: {
        type: String,
        required: true,
    },
    uploadedAt: {
        type: Date,
        default: Date.now,
    },
    totalRequests: Number,
    uniqueIPs: Number,
    errorCount: Number,

    // Агрегированные данные для графиков
    requestsByHour: [{ hour: Number, count: Number }],
    statusCodes: {
        '2xx': Number,
        '3xx': Number,
        '4xx': Number,
        '5xx': Number,
    },
    topIPs: [{
        ip: String,
        count: Number,
        errors: Number,
        flag: String, // 'suspicious' | 'watch' | 'normal'
        country: String,
        city: String,
    }],
    topEndpoints: [{
        path: String,
        count: Number,
        errorCount: Number,
    }],

    anomalies: [anomalySchema],

    // Сырые записи (первые 1000 для таблицы)
    entries: [rawEntrySchema],
});

module.exports = mongoose.model('Log', logSchema);