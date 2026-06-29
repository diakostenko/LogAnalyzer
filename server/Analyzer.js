// принимает распаршенные данные и возвращает стату
function analyze(entries) {
    if (!entries.length) {
        return {
            totalRequests: 0,
            uniqueIPs: 0,
            errorCount: 0,
            requestsByHour: [],
            statusCodes: { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 },
            topIPs: [],
            topEndpoints: [],
            anomalies: [],
        };
    }

    // Базовые счётчики
    const ipMap = {};         // ip -> { count, errors }
    const endpointMap = {};   // path -> { count, errorCount }
    const hourMap = {};       // hour (0-23) -> count
    const minuteMap = {};     // "YYYY-MM-DDTHH:MM" -> count (для пиков)
    const statusCodes = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
    let errorCount = 0;

    for (const entry of entries) {
        const { ip, timestamp, path, status } = entry;

        // Статус-коды
        if (status >= 200 && status < 300) statusCodes['2xx']++;
        else if (status >= 300 && status < 400) statusCodes['3xx']++;
        else if (status >= 400 && status < 500) { statusCodes['4xx']++; errorCount++; }
        else if (status >= 500) { statusCodes['5xx']++; errorCount++; }

        // По часам
        const hour = timestamp.getUTCHours();
        hourMap[hour] = (hourMap[hour] || 0) + 1;

        // По минутам (для детекции пика)
        const minuteKey = timestamp.toISOString().slice(0, 16); // "2024-10-10T13:55"
        minuteMap[minuteKey] = (minuteMap[minuteKey] || 0) + 1;

        // По IP
        if (!ipMap[ip]) ipMap[ip] = { count: 0, errors: 0, endpoints: new Set() };
        ipMap[ip].count++;
        if (status >= 400) ipMap[ip].errors++;
        ipMap[ip].endpoints.add(path);

        // По эндпоинтам
        if (!endpointMap[path]) endpointMap[path] = { count: 0, errorCount: 0 };
        endpointMap[path].count++;
        if (status >= 400) endpointMap[path].errorCount++;
    }

    // Топ IP
    const avgRequestsPerIP = entries.length / Object.keys(ipMap).length;
    const SUSPICIOUS_THRESHOLD = Math.max(avgRequestsPerIP * 5, 200);
    const WATCH_THRESHOLD = Math.max(avgRequestsPerIP * 2, 100);

    const topIPs = Object.entries(ipMap)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 20)
        .map(([ip, data]) => ({
            ip,
            count: data.count,
            errors: data.errors,
            flag: data.count >= SUSPICIOUS_THRESHOLD
                ? 'suspicious'
                : data.count >= WATCH_THRESHOLD
                    ? 'watch'
                    : 'normal',
        }));

    // Топ эндпоинтов
    const topEndpoints = Object.entries(endpointMap)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 20)
        .map(([path, data]) => ({ path, ...data }));

    // Запросы по часам (массив 0-23)
    const requestsByHour = Array.from({ length: 24 }, (_, i) => ({
        hour: i,
        count: hourMap[i] || 0,
    }));

    // Детекция аномалий
    const anomalies = detectAnomalies({
        entries,
        ipMap,
        endpointMap,
        minuteMap,
        hourMap,
        statusCodes,
        avgRequestsPerIP,
        SUSPICIOUS_THRESHOLD,
    });

    return {
        totalRequests: entries.length,
        uniqueIPs: Object.keys(ipMap).length,
        errorCount,
        requestsByHour,
        statusCodes,
        topIPs,
        topEndpoints,
        anomalies,
    };
}

function detectAnomalies({ entries, ipMap, endpointMap, minuteMap, statusCodes, SUSPICIOUS_THRESHOLD }) {
    const anomalies = [];

    // 1. Пик трафика — минута с резким превышением среднего
    const minuteCounts = Object.values(minuteMap);
    if (minuteCounts.length > 1) {
        const avgPerMinute = minuteCounts.reduce((a, b) => a + b, 0) / minuteCounts.length;
        const maxMinute = Math.max(...minuteCounts);
        const peakKey = Object.entries(minuteMap).find(([, v]) => v === maxMinute)?.[0];

        if (maxMinute > avgPerMinute * 5) {
            anomalies.push({
                type: 'traffic_spike',
                severity: 'critical',
                title: `Пик трафика в ${peakKey?.slice(11)} — превышение нормы в ${Math.round(maxMinute / avgPerMinute)}×`,
                description: `${maxMinute} запросов за 1 минуту при средней норме ${Math.round(avgPerMinute)}/мин. Вероятно: DDoS или боты.`,
            });
        }
    }

    // 2. Брутфорс — IP с высокой долей 4xx ошибок и большим числом запросов
    for (const [ip, data] of Object.entries(ipMap)) {
        const errorRate = data.errors / data.count;
        if (data.count >= 200 && errorRate >= 0.8) {
            anomalies.push({
                type: 'bruteforce',
                severity: 'critical',
                title: `Брутфорс с ${ip} — ${data.count} запросов, ${Math.round(errorRate * 100)}% ошибок`,
                description: `IP сделал ${data.errors} запросов с кодом 4xx из ${data.count}. Признак перебора паролей или сканирования.`,
            });
        }
    }

    // 3. Сканирование эндпоинтов — путь с почти 100% ошибок и приличным трафиком
    for (const [path, data] of Object.entries(endpointMap)) {
        const errorRate = data.errorCount / data.count;
        if (data.count >= 50 && errorRate >= 0.95) {
            anomalies.push({
                type: 'scan',
                severity: 'warning',
                title: `Сканирование ${path} — ${data.count} запросов, все с ошибкой`,
                description: `${data.errorCount} из ${data.count} запросов вернули ошибку. Возможно: автоматический сканер уязвимостей.`,
            });
        }
    }

    // 4. Рост ошибок 5xx — проблемы на сервере
    const total = entries.length;
    const serverErrorRate = statusCodes['5xx'] / total;
    if (statusCodes['5xx'] >= 50 && serverErrorRate >= 0.02) {
        anomalies.push({
            type: 'server_error',
            severity: 'warning',
            title: `Повышенный уровень ошибок 5xx — ${statusCodes['5xx']} случаев (${Math.round(serverErrorRate * 100)}%)`,
            description: `Сервер вернул ${statusCodes['5xx']} ошибок 5xx. Возможный сбой приложения или базы данных.`,
        });
    }

    return anomalies;
}

module.exports = { analyze };