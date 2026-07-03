// принимает массив распаршенных данных, возвращает анализ и аномалии
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

    const ipMap = {};
    const endpointMap = {};
    const hourMap = {};
    const minuteMap = {};
    const statusCodes = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
    let errorCount = 0;
    const ipPathErrorMap = {};   // ip -> { path -> count } для 4xx
    const ipUniquePathsMap = {}; // ip -> Set путей
    const ip404Map = {};         // ip -> count 404

    for (const entry of entries) {
        const { ip, timestamp, path, status } = entry;

        // статус-коды
        if (status >= 200 && status < 300) statusCodes['2xx']++;
        else if (status >= 300 && status < 400) statusCodes['3xx']++;
        else if (status >= 400 && status < 500) { statusCodes['4xx']++; errorCount++; }
        else if (status >= 500) { statusCodes['5xx']++; errorCount++; }

        // по часам
        const hour = timestamp.getUTCHours();
        hourMap[hour] = (hourMap[hour] || 0) + 1;

        // по минутам
        const minuteKey = timestamp.toISOString().slice(0, 16);
        minuteMap[minuteKey] = (minuteMap[minuteKey] || 0) + 1;

        // по IP
        if (!ipMap[ip]) ipMap[ip] = { count: 0, errors: 0, errors4xx: 0, errors5xx: 0 };
        ipMap[ip].count++;
        if (status >= 400 && status < 500) { ipMap[ip].errors++; ipMap[ip].errors4xx++; }
        if (status >= 500) { ipMap[ip].errors++; ipMap[ip].errors5xx++; }

        // уникальные пути на IP
        if (!ipUniquePathsMap[ip]) ipUniquePathsMap[ip] = new Set();
        ipUniquePathsMap[ip].add(path);

        // 4xx по пути на IP (для брутфорс-детекции)
        if (status >= 400 && status < 500) {
            if (!ipPathErrorMap[ip]) ipPathErrorMap[ip] = {};
            ipPathErrorMap[ip][path] = (ipPathErrorMap[ip][path] || 0) + 1;
        }

        // 404 на IP (для сканер-детекции)
        if (status === 404) {
            ip404Map[ip] = (ip404Map[ip] || 0) + 1;
        }

        // по эндпоинтам
        if (!endpointMap[path]) endpointMap[path] = { count: 0, errorCount: 0 };
        endpointMap[path].count++;
        if (status >= 400) endpointMap[path].errorCount++;
    }

    // топ ip
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
            flag: data.count >= SUSPICIOUS_THRESHOLD ? 'suspicious'
                : data.count >= WATCH_THRESHOLD ? 'watch'
                    : 'normal',
        }));

    // топ эндпоинтов
    const topEndpoints = Object.entries(endpointMap)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 20)
        .map(([path, data]) => ({ path, ...data }));

    // запросы по часам
    const requestsByHour = Array.from({ length: 24 }, (_, i) => ({
        hour: i,
        count: hourMap[i] || 0,
    }));

    // аномалии
    const anomalies = detectAnomalies({
        entries,
        ipMap,
        ipPathErrorMap,
        ipUniquePathsMap,
        ip404Map,
        endpointMap,
        minuteMap,
        statusCodes,
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

function detectAnomalies({ entries, ipMap, ipPathErrorMap, ipUniquePathsMap, ip404Map, minuteMap, statusCodes }) {
    const anomalies = [];

    // пик трафика
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

    // брутфорс
    for (const [ip, data] of Object.entries(ipMap)) {
        const clientErrorRate = data.errors4xx / data.count;
        if (data.count < 100 || clientErrorRate < 0.7) continue;

        const pathCounts = Object.values(ipPathErrorMap[ip] || {});
        const totalErrors4xx = pathCounts.reduce((a, b) => a + b, 0);
        const maxPathCount = pathCounts.length ? Math.max(...pathCounts) : 0;
        const concentration = totalErrors4xx > 0 ? maxPathCount / totalErrors4xx : 0;

        if (concentration >= 0.5) {
            const topPath = Object.entries(ipPathErrorMap[ip] || {})
                .sort((a, b) => b[1] - a[1])[0]?.[0] || '?';
            anomalies.push({
                type: 'bruteforce',
                severity: 'critical',
                title: `Брутфорс с ${ip} — ${data.count} запросов на ${topPath}`,
                description: `${data.errors4xx} запросов с кодом 4xx из ${data.count} (${Math.round(clientErrorRate * 100)}%), большинство направлены на один эндпоинт. Признак перебора паролей.`,
            });
        }
    }

    // сканирование
    for (const [ip, data] of Object.entries(ipMap)) {
        const uniquePaths = ipUniquePathsMap[ip]?.size || 0;
        const notFoundCount = ip404Map[ip] || 0;
        const notFoundRate = notFoundCount / data.count;

        if (data.count >= 30 && uniquePaths >= 5 && notFoundRate >= 0.5) {
            anomalies.push({
                type: 'scan',
                severity: 'warning',
                title: `Сканирование с ${ip} — ${uniquePaths} уникальных путей, ${Math.round(notFoundRate * 100)}% ответов 404`,
                description: `IP перебирает разные пути (${data.count} запросов, ${notFoundCount} ошибок 404). Признак автоматического сканера уязвимостей.`,
            });
        }
    }

    // повышенный уровень 5xx
    const total = entries.length;
    const serverErrorRate = statusCodes['5xx'] / total;
    if (statusCodes['5xx'] >= 50 && serverErrorRate >= 0.02) {
        anomalies.push({
            type: 'server_error',
            severity: 'warning',
            title: `Повышенный уровень ошибок 5xx — ${statusCodes['5xx']} случаев (${Math.round(serverErrorRate * 100)}%)`,
            description: `Сервер вернул ${statusCodes['5xx']} ошибок 5xx. Возможный сбой приложения или базы данных в период пика.`,
        });
    }

    return anomalies;
}

module.exports = { analyze };