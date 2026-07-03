require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const logsRouter = require('./routes/logs');

const app = express();
const PORT = process.env.PORT || 3000;

// middleware
app.use(cors());
app.use(express.json());

// фронтенд
app.use(express.static(path.join(__dirname, '../client')));

// роутер
app.use('/api/logs', logsRouter);

// спа
app.get('/{*splat}', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
});

// подключение к MongoDB
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
