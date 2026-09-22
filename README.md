# CSQTT VPN Desktop

[![Boosty](https://img.shields.io/badge/Boosty-Support%20development-FF7143?style=for-the-badge&logo=boosty&logoColor=white)](https://boosty.to/danusha/donate)

Репозиторий desktop-клиента: [`danusha2345/csqtt-vpn`](https://github.com/danusha2345/csqtt-vpn).
Android-клиент и сервер нашей сборки: [`danusha2345/csqtt-android`](https://github.com/danusha2345/csqtt-android).

Десктопный клиент CSQTT для Windows и Linux. GUI на Wails управляет официальным
Rust transport из [`amurcanov/csqtt`](https://github.com/amurcanov/csqtt),
создаёт системный TUN и отправляет IPv4-трафик через CSQTT/VK TURN.

Версия desktop bundle: **2.1.16**, bundled Rust core: **2.1.11**. Каждый пользователь
вводит endpoint собственного сервера; стандартный формат — `host:46010`.

## Архитектура

### Windows

```text
приложения → Wintun CSQTT → raw-IP UDP bridge 127.0.0.1:19000
            → csqtt-client.exe → VK TURN → CSQTT server → интернет
```

GUI устанавливает split-default routes, NRPT/DNS и IPv6 leak guard. Адрес
сервера, сети VK и обнаруженные TURN relay получают bypass через физический
gateway. При падении transport или Wintun маршруты и DNS снимаются fail-safe.

### Linux

```text
приложения → /dev/net/tun (csqtt0) → TUN FD через abstract UDS/SCM_RIGHTS
            → csqtt-client → VK TURN → CSQTT server → интернет
```

Linux backend использует нативный `--tun-uds` Rust-клиента, `iproute2` и
`systemd-resolved`. Split routes, DNS и IPv6 leak guard откатываются при
отключении или завершении transport. Для TUN и маршрутов GUI пока запускается с
root-правами; privilege-separated helper — отдельная следующая итерация.

Пароль и VK call links desktop-оболочка передаёт transport-процессу через
одноразовый JSON в `stdin` (`--credentials-stdin`), а не через process argv.

## Содержимое release bundle

Windows:

```text
CSQTT-VPN.exe
bin/csqtt-client.exe
wintun.dll
```

Нужны Windows 10/11 и WebView2 Runtime. `CSQTT-VPN.exe` содержит manifest
`requireAdministrator`. `wintun.dll` должен находиться именно рядом с
`CSQTT-VPN.exe`: библиотека Wintun загружается из каталога приложения, а не из
подкаталога `bin`.

Linux:

```text
CSQTT-VPN
bin/csqtt-client
```

Нужны `iproute2`, `systemd-resolved`, GTK 3 и WebKitGTK 4.1. Rust transport
собран статически под musl; Wails GUI использует системные GTK/WebKit библиотеки.
Запуск текущей версии:

```bash
sudo -E ./CSQTT-VPN
```

## Возможности GUI

- профили сервера, пароля, VK links и исключений;
- `audio`/`video` obfuscation и TURN `UDP`/`TCP-TLS`;
- от 9 до 126 workers с нормализацией до кратного 9;
- системный TUN, DNS proxy и маршрутизация доменов/IP/CIDR напрямую;
- журнал, диагностика, скорость и объём текущей сессии; сводка трафика
  закреплена над историей журнала и обновляется без добавления новых строк,
  длинный текст в верхней панели переносится целиком;
- Windows autostart (на Linux скрыт до появления privilege-separated helper);
- проверка обновлений нашего GitHub release, загрузка с progress и установка
  полного Windows bundle через helper с rollback после явного выбора в UI.

Контракт assets, восстановление и обязательный Windows release gate:
[docs/WINDOWS_UPDATER.md](docs/WINDOWS_UPDATER.md).

## Сборка

Требуются Go 1.25+, Node.js/npm, Wails 2.13 и Rust 1.97.1. Frontend:

```bash
cd frontend
npm ci
npm audit
npm run build
```

Проверки Go:

```bash
go test ./...
go test -race ./core
go vet ./...
GOOS=windows GOARCH=amd64 go test -c ./core
```

Windows GUI:

```bash
mv rsrc_windows_amd64.syso /tmp/
wails build -platform windows/amd64 -trimpath
mv /tmp/rsrc_windows_amd64.syso .
```

Linux GUI:

```bash
wails build -platform linux/amd64 -tags webkit2_41 \
  -trimpath -clean=false
```

Rust core собирается из `rust-client/` репозитория CSQTT:

```bash
cargo build --release --locked --target x86_64-pc-windows-gnu
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl
```

Оптимизации запуска описаны в [WINDOWS_PERFORMANCE.md](docs/WINDOWS_PERFORMANCE.md).
Updater впервые входит в 2.1.12: эту версию нужно установить вручную целиком;
последующие стабильные версии проверяются и устанавливаются из приложения.

## Ограничения проверки

В версии `2.1.11` исправлены применение DNS из `TUNCONF`, TCP fallback
при усечённом DNS-ответе и обработка ошибок Windows IPv6 guard: ошибка теперь
прерывает подключение с откатом. Используйте core из того же bundle и сервер
`danusha2345/csqtt-android`; upstream server `amurcanov/csqtt 2.1.9` имеет другой
wire protocol и отклоняет подключение с `DENIED:protocol_mismatch`.

Unit/race/cross-compile, frontend audit/build, Wintun PE build, Linux TUN namespace
и SCM_RIGHTS проверяются локально. Полный TURN e2e требует действующей VK call
link/hash; секреты в тесты и репозиторий не включаются.

CSQTT core распространяется по лицензии upstream PolyForm Noncommercial 1.0.0.
Исходный проект и автор протокола: [`amurcanov/csqtt`](https://github.com/amurcanov/csqtt).
