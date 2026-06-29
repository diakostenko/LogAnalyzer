require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const logsRouter = require('./routes/logs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Статические файлы фронта
app.use(express.static(path.join(__dirname, '../client')));

// API роуты
app.use('/api/logs', logsRouter);

// Для всех остальных запросов отдаём index.html (SPA-подход)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
});

// Подключение к MongoDB
mongoose
    .connect(process.env.MONGO_URI || 'mongodb://localhost:27017/loganalyzer')
    .then(() => {
        console.log('MongoDB подключена');
        app.listen(PORT, () => {
            console.log(`Сервер запущен на http://localhost:${PORT}`);
        });
    })
    .catch((err) => {
        console.error('Ошибка подключения к MongoDB:', err.message);
        process.exit(1);
    });