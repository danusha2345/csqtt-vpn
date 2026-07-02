# WDTT VPN

Десктопный VPN-клиент для WDTT (**Windows**, GUI на Wails) — туннелирует трафик
через TURN-серверы VK, маскируя соединение под зашифрованный медиатрафик звонка.

Использует то же Go-ядро (`wdtt-client`), что и Android-версия
[danusha2345/proxy-turn-vk-android](https://github.com/danusha2345/proxy-turn-vk-android):
бинарь `bin/wdtt-client.exe` собирается из её `go_client/` и включает VK Calls
captcha-free path. Полную карту проектов семейства см. в разделе
[Проекты семейства WDTT](#проекты-семейства-wdtt).

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
- **Подключение без капчи (VK Calls):** клиент по умолчанию получает TURN-креды
  анонимным path через `api.vk.me` (`-vk-auth-mode=vkcalls`) — VK Smart Captcha
  вообще не запрашивается. Если VK Calls недоступен, идёт fallback на прежний VK Auth
  с авто-решателем капчи (`-captcha-mode auto`: Go v2 → Auto WebView → ручной).
  Режим включён из коробки; GUI отдельного тумблера не выводит и полагается на дефолт
  ядра `go_client`.
- **GUI** на Wails: тёмная тема, профили серверов, автозапуск, метрики трафика, диагностика.
- Self-contained: WireGuard ставить не нужно (userspace). Нужен свой WDTT-сервер.

## Устойчивость и нагрузка (торренты)

`wireproxy` (userspace WireGuard + SOCKS5) под валом одновременных соединений —
типично **BitTorrent/DHT** (сотни коннектов на порты 6881/51413/6969/2710) — может
упасть с `exit status 2` (паника/OOM). Без живого SOCKS5 на `127.0.0.1:1080`
`tun2socks` превращает сеть в «чёрную дыру»: весь трафик уходит в мёртвый прокси
(`wsarecv: forcibly closed`), интернет пропадает.

Поэтому ядро (`core/core.go`):

- **Супервайзер** `superviseWireproxy` перезапускает упавший `wireproxy` на том же
  порту (backoff, до 5 попыток подряд) — `tun2socks` и маршруты восстанавливаются
  сами, маршруты трогать не нужно. Счётчик сбрасывается, если процесс прожил >60 с.
- **Fail-safe**: если перезапуски не помогают, VPN гасится (снимаются `tun2socks` и
  системные маршруты, возвращается прямой интернет), GUI через `onDown` возвращает
  кнопку в «Подключить» — лучше прямой интернет, чем «чёрная дыра».

> На уровне Windows-маршрутов резать трафик **по портам** нельзя (`route` работает по
> IP, а `tun2socks` ловит весь диапазон `0.0.0.0/1`+`128.0.0.0/1`), поэтому
> торрент-шторм программно не отфильтровать. Если качаете торренты — либо выключайте
> их при активном VPN, либо настройте bind торрент-клиента мимо туннеля. Супервайзер
> делает такой краш не фатальным, но не бесплатным.

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

### Сборка клиентского бинаря `bin/wdtt-client.exe`

Ядро клиента берётся из соседнего репозитория
[proxy-turn-vk-android](https://github.com/danusha2345/proxy-turn-vk-android)
(модуль `go_client/`, требует Go 1.26+):

```bash
cd proxy-turn-vk-android/go_client
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o wdtt-client.exe .
# затем положить рядом с WDTT-VPN.exe в bin/
```

`wireproxy.exe`, `tun2socks.exe`, `wintun.dll` — готовые сторонние бинари, пересборка
не нужна (см. `wdtt-windows-client/README.md` для источников и версий).

## Проекты семейства WDTT

WDTT (**W**ireGuard **o**ver **T**URN **T**unnel) — семейство клиентов с общим Go-ядром
и общим сервером. Все они гоняют WireGuard через TURN-серверы VK-звонков.

| Проект | Платформа | Роль |
|--------|-----------|------|
| [danusha2345/proxy-turn-vk-android](https://github.com/danusha2345/proxy-turn-vk-android) | Android | **Основной репозиторий**: приложение (APK), Go-ядро `go_client/` (общий клиент) и `server.go` (WDTT-сервер) |
| **wdtt-vpn** (этот репозиторий) | Windows (Linux — только GUI) | Десктопный GUI на Wails |
| `wdtt-windows-client` | Windows | Ранний CLI/лаунчер-порт; вытеснен этим проектом, оставлен как справка по helper-бинарям |
| `wdtt-linux-client` | Linux | Рабочий Linux-GUI на Python |
| [cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) | — | Upstream-первоисточник протокола (VK TURN over DTLS) |

Клиент и сервер собираются из ядра `proxy-turn-vk-android`; десктопные/CLI-обёртки
лишь запускают этот бинарь и настраивают маршрутизацию под свою ОС.
