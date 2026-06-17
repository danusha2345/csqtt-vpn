# WDTT VPN

Десктопный VPN-клиент для WDTT — туннелирует трафик через TURN-серверы VK,
маскируя соединение под зашифрованный медиатрафик звонка. Форк/порт
[proxy-turn-vk-android](https://github.com/amurcanov/proxy-turn-vk-android).

> **Платформы:** полностью работает под **Windows**. Linux-таргет *компилируется*, но
> системный VPN под не-Windows — заглушка (`core/tun_other.go`: `startSystemRouting`
> возвращает «поддерживается только на Windows»), а helper-бинари в `bin/` только под
> Windows (`.exe`), причём `Manager.exe()` не убирает суффикс `.exe`. Для рабочего
> Linux-GUI используйте отдельный проект `wdtt-linux-client` (Python).

## Архитектура

```
трафик → TUN (tun2socks) → SOCKS5 (wireproxy, userspace WireGuard)
       → wdtt-client (VK TURN) → wdtt-server (ваш VPS) → интернет
```

- **Системный VPN** со split-маршрутизацией (трафик клиента к VK идёт мимо туннеля).
- **DNS-перехват** для обхода по доменам, блокировка IPv6-утечки.
- **GUI** на Wails: тёмная тема, профили серверов, автозапуск, метрики трафика, диагностика.
- Self-contained: WireGuard ставить не нужно (userspace). Нужен свой WDTT-сервер.

## Сборка

Требуется Go 1.24+, Node 18+, Wails CLI v2.12 (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`).

### Windows (.exe) — основной таргет, кросс-сборка с Linux

```bash
# ВАЖНО: в корне лежит ручной rsrc_windows_amd64.syso. wails генерит СВОЙ ресурс →
# две .rsrc-секции → линкер падает с "too many .rsrc sections". Убрать на время сборки:
mv rsrc_windows_amd64.syso /tmp/ 2>/dev/null
wails build -platform windows/amd64
mv /tmp/rsrc_windows_amd64.syso . 2>/dev/null
```

Результат: `build/bin/WDTT-VPN.exe`. Рядом с ним должна быть папка `bin/`
(wdtt-client.exe, wireproxy.exe, tun2socks.exe, wintun.dll). Нужен WebView2 Runtime
(есть в Windows 10/11).

### Linux (только GUI, без VPN-функций — см. оговорку выше)

```bash
# wails по умолчанию ищет webkit2gtk-4.0; на свежих дистрибутивах только 4.1 → тег webkit2_41
wails build -platform linux/amd64 -tags webkit2_41
```

Результат: `build/bin/WDTT-VPN`. Зависимости: `libgtk-3`, `libwebkit2gtk-4.1`.

> Альтернатива (ручная сборка .exe без wails, с готовым .syso для иконки):
> `cd frontend && npm install && npm run build && cd .. && CGO_ENABLED=0 GOOS=windows`
> `GOARCH=amd64 go build -tags "desktop,production" -buildvcs=false -ldflags "-H windowsgui -s -w" -o WDTT-VPN.exe .`
