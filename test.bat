@echo off
chcp 65001 >nul
title Kiem thu SecNet
setlocal

rem =====================================================================
rem  SECNET: kiem thu toan bo tinh nang cua he thong dang chay bang Docker
rem
rem  Cach dung:
rem    test.bat          kiem thu nhanh (~1 phut): container, API, web, TLS, CSDL,
rem                      dang nhap, RBAC, WebSocket, phat hien tan cong, luat,
rem                      blocklist, kenh thong bao
rem    test.bat notify   nhu tren + gui "test alert" that qua moi kenh dang bat
rem                      (Email, Telegram, Slack, Webhook)
rem    test.bat full     nhu tren + chay bo test Rust (cargo test) trong Docker
rem    test.bat all      notify + full
rem
rem  Can chay start_docker.bat truoc. Ket qua luu vao test_report.txt
rem =====================================================================

cd /d "%~dp0"

set "PS_ARGS="
if /i "%~1"=="notify" set "PS_ARGS=-SendNotifications"
if /i "%~1"=="full"   set "PS_ARGS=-Full"
if /i "%~1"=="all"    set "PS_ARGS=-Full -SendNotifications"

where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo [LOI] Khong tim thay Docker. Cai Docker Desktop tu https://www.docker.com/
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\test_system.ps1" %PS_ARGS%
set "RESULT=%errorlevel%"

echo.
if "%RESULT%"=="0" (
    echo  Tat ca kiem thu deu dat.
) else (
    echo  Co kiem thu that bai. Xem chi tiet o tren hoac trong test_report.txt
)
echo.
pause
exit /b %RESULT%
