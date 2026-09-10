// Обновляем только сводку трафика: сетевые ошибки остаются в истории журнала.
const trafficSummary = /^(?:\[client\]\s*)?\[(?:СТАТИСТИКА|СЕТЬ)\]\s*Активных:\s*\d+\s*\|\s*Трафик:/;

export function replaceTrafficLogLine(entries, line) {
    if (!trafficSummary.test(line)) return false;
    const entry = entries.find((item) => trafficSummary.test(item.line));
    if (!entry) return false;
    entry.line = line;
    entry.count = 1;
    entry.dirty = true;
    return true;
}
