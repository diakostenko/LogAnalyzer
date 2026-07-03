const fs = require('fs');
const readline = require('readline');

const LOG_REGEX =
    /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+|-)/;

function parseLogDate(dateStr) {
    const months = {
        Jan: '01', Feb: '02', Mar: '03', Apr: '04',
        May: '05', Jun: '06', Jul: '07', Aug: '08',
        Sep: '09', Oct: '10', Nov: '11', Dec: '12',
    };
    // "10/Oct/2024:13:55:36 +0000" -> "2024-10-10T13:55:36+00:00"
    const match = dateStr.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/);
    if (!match) return null;
    const [, day, mon, year, time] = match;
    return new Date(`${year}-${months[mon]}-${day}T${time}Z`);
}

// читает файл построчно, возвращает распаршенные данные
async function parseLogFile(filePath) {
    const entries = [];
    const skipped = [];

    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    for await (const line of rl) {
        if (!line.trim()) continue;

        const match = line.match(LOG_REGEX);
        if (!match) {
            skipped.push(line);
            continue;
        }

        const [, ip, dateStr, method, path, statusStr, sizeStr] = match;
        const timestamp = parseLogDate(dateStr);
        const status = parseInt(statusStr, 10);
        const size = sizeStr === '-' ? 0 : parseInt(sizeStr, 10);

        if (!timestamp) continue;

        entries.push({ ip, timestamp, method, path, status, size });
    }

    if (skipped.length > 0) {
        console.warn(`Пропущено ${skipped.length} нераспознанных строк`);
    }

    return entries;
}

module.exports = { parseLogFile };