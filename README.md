# WDTT VPN

Десктопный VPN-клиент (Windows/Linux) для WDTT — туннелирует трафик через TURN-серверы VK,
маскируя соединение под зашифрованный медиатрафик звонка. Форк/порт
[proxy-turn-vk-android](https://github.com/amurcanov/proxy-turn-vk-android).

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

```bash
cd frontend && npm install && npm run build && cd ..
# Windows (кросс с Linux):
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags "desktop,production" \
  -buildvcs=false -ldflags "-H windowsgui -s -w" -o WDTT-VPN.exe .
```

Рядом с `WDTT-VPN.exe` должна быть папка `bin/` (wdtt-client.exe, wireproxy.exe, tun2socks.exe, wintun.dll).
На Windows нужен WebView2 Runtime (есть в Windows 10/11).
