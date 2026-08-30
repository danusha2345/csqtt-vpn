# Changelog

## 2.1.7 — 2026-08-30

- удалён адрес частного сервера из defaults, README и release notes;
- endpoint собственного сервера теперь вводится пользователем явно;
- Windows и Linux bundles добавлены в единый release `csqtt-android`.

## 2.1.6 — 2026-08-30

- первый CSQTT desktop release для Windows и Linux;
- Wintun raw-IP bridge на Windows;
- нативный TUN FD transport через abstract UDS/SCM_RIGHTS на Linux;
- системные split routes, DNS proxy и IPv6 leak guard с fail-safe cleanup;
- TURN UDP и TCP/TLS, audio/video obfuscation, 9–126 workers;
- стабильный приватный device ID на установку;
- password и VK links передаются Rust transport через stdin, а не process argv;
- новый CSQTT GUI, profiles, diagnostics и session traffic metrics;
