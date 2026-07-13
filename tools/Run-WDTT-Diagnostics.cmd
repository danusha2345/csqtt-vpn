@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
title WDTT Diagnostics
set "WDTT_OUT=%TEMP%\WDTT-Diagnostics"
set "WDTT_LAUNCH_LOG=%WDTT_OUT%\launcher-latest.txt"
if not exist "%WDTT_OUT%" mkdir "%WDTT_OUT%" >nul 2>&1
echo.
echo Включите WDTT VPN и воспроизведите проблему ДО запуска диагностики.
echo Утилита только читает состояние Windows и ничего не меняет.
echo.
set /p "WDTT_DOMAINS=Проблемные домены через запятую (можно оставить пустым): "
echo.
echo Идет сбор диагностики. Это может занять 1-2 минуты...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0WDTT-Diagnostics.ps1" -Domains "%WDTT_DOMAINS%" -OutputDirectory "%WDTT_OUT%" >"%WDTT_LAUNCH_LOG%" 2>&1
set "WDTT_EXIT=%ERRORLEVEL%"
type "%WDTT_LAUNCH_LOG%"
echo.
echo Код завершения PowerShell: %WDTT_EXIT%
echo Отчет и launcher-latest.txt находятся здесь:
echo %WDTT_OUT%
start "" explorer.exe "%WDTT_OUT%"
pause
