# Desktop с core 2.5

Ветка `feature/upstream-2.5-all`, `2.5.0-dev.1`, исходный desktop
`26ab765e4e7116fd35707ac1478c872b67c16787`.
Нужен сервер из одноимённой ветки android-server с `CSQTT-WIRE-4`.
Старые серверы и upstream-серверы не поддерживаются этой интеграцией.

Добавлены SRTP `auto/wrap/dtls`, TURN IPv4 pool, unified obfuscation и
workers 3–100. TURN IPv4 и IPv4:port проверяются до подключения и получают
bypass до установки VPN routes. IPv6/hostname в этом поле отклоняются:
текущий desktop bridge поддерживает IPv4. Domain exclusions по-прежнему
реализованы системными маршрутами/DNS, чтобы direct sockets не зацикливались
в собственном VPN.

Сохранены Auto API/Auto VK, credentials stdin, graceful STOP/FINISH_VK_CALLS,
обновление по проверенному SHA-256 и одна обновляемая строка трафика.
Bundle должен содержать соответствующий `bin/csqtt-client[.exe]`;
`core_identity.json` фиксирует версию и SHA-256 обоих native binaries.

Проверки: Go test/race/vet, frontend build/traffic tests, native Linux/Windows
builds. Локальный настоящий сервер проверяется в android-server через
`scripts/test_local_transport.sh`: WRAP/DTLS, фрагментация и SOCKS5.
Это не подтверждает реальную VPN-сессию на Windows, UAC, VK TURN или игры.
Деплой и публикация для этой ветки не выполнялись.

Финальный transport дополнительно связывает DTLS exporter с паролем сервера
через TLS 1.2 PRF с отдельным label CSQTT-WIRE-4. Один самоподписанный DTLS
сертификат не подтверждает сервер: без пароля подставной peer не получает
ключи регистрации и трафика. Core и сервер должны быть из этой ветки вместе.

Итоговые проверки: Go test/race/vet, кросс-компиляция Go core tests под Windows,
frontend traffic tests и build, npm audit без найденных уязвимостей. Windows и
Linux GUI пересобраны с окончательным core; проверены core identity внутри GUI,
UAC manifest, состав и побайтовое чтение ZIP/tar обратно. Windows VPN/UAC runtime
и работа с реальным VK TURN остаются вне этого локального прогона.
