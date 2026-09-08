# Оптимизации Windows в 2.1.12

- Cleanup объединяет шесть PowerShell-процессов в один. Сохраняются фильтр
  точного executable path, alias CSQTT и признаки managed NRPT.
- Четыре split route создаются одним PowerShell-процессом по порядку IPv4/IPv6,
  с `ErrorAction Stop` и проверкой наличия каждого маршрута. Ошибка вызывает откат.
- Ожидание адаптера сразу возвращает ifIndex; отдельный запрос индекса удалён.
- На обычном пути без повторных polls получается около 6 PowerShell-запусков
  вместо 15. Это подсчёт вызовов по исходникам, не измеренное ускорение в секундах.
- Статистика больше не запускает PowerShell каждые 1,5 секунды. Atomic counters
  считают IP-байты, успешно переданные между TUN и UDP bridge; dropped packets
  и внешние protocol headers не учитываются. Новый bridge начинает с нуля.
- Setup-команды следуют cancellation/timeout Connect; выход core также отменяет
  setup. Cleanup имеет независимый ограниченный timeout для восстановления сети.
- DNS-кэш ограничен 1024 записями, не сохраняет TTL=0 и возвращает оставшийся TTL.
  Запросы с EDNS/DNSSEC опциями не берутся из общего кэша. TCP fallback сохраняется.
- `[STARTUP]` в журнале показывает cleanup, первый CONFIG и routing-ready.
  Последний milestone не является доказательством первого успешного VPN-пакета.

Тесты проверяют scope/quoting batch scripts, строгие route checks, отмену
subprocess, лимит/TTL DNS-кэша, concurrent counters и identity bundled core.
Реальный выигрыш измеряется на одинаковых Windows, сервере, VK links и workers:
не менее 20 cold/warm подключений, p50/p95 и первый tunneled DNS/HTTPS отдельно.
Pacing/retry Rust, Wintun ownership и обфускация в этой версии не менялись.
