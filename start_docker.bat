@echo off
chcp 65001 >nul
title Khởi chạy SecNet bằng Docker

echo =====================================================================
echo  🛡️ SECNET: Real-time Network Security Analytics ^& Alerting System
echo =====================================================================
echo.

:: Kiểm tra Docker đã cài đặt chưa
where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo [LỖI] Không tìm thấy Docker! Vui lòng cài đặt Docker Desktop từ https://www.docker.com/
    pause
    exit /b 1
)

:: Kiểm tra Docker daemon có đang chạy không
docker info >nul 2>nul
if %errorlevel% neq 0 (
    echo [CẢNH BÁO] Docker Desktop chưa khởi động!
    echo Vui lòng mở ứng dụng Docker Desktop trên Windows và đợi "Engine running", sau đó chạy lại file này.
    pause
    exit /b 1
)

:: Tạo file .env nếu chưa có
if not exist .env (
    echo [*] Chưa tìm thấy file .env, đang sao chép từ .env.example...
    copy .env.example .env >nul
)

echo [*] Đang build và khởi chạy toàn bộ 6 dịch vụ (TimescaleDB, Redis, Backend, Frontend, Nginx TLS, Capture Engine)...
docker compose up --build -d

if %errorlevel% neq 0 (
    echo.
    echo [LỖI] Khởi chạy thất bại! Vui lòng kiểm tra log lỗi bên trên.
    pause
    exit /b 1
)

echo.
echo =====================================================================
echo  ✅ HỆ THỐNG ĐÃ KHỞI CHẠY THÀNH CÔNG!
echo =====================================================================
echo.
echo  🌐 Dashboard Web SOC:     http://localhost:3000
echo  📖 Tài liệu Swagger API:  http://localhost:8080/swagger-ui
echo  📈 Prometheus Metrics:    http://localhost:8080/metrics
echo.
echo  🔑 Tài khoản đăng nhập mặc định:
echo     - Admin:   admin        / Admin@SecNet2026!
echo     - Analyst: analyst_linh / Analyst@SecNet2026!
echo     - Viewer:  viewer_demo  / Viewer@SecNet2026!
echo.
echo =====================================================================
echo  Đang mở trình duyệt vào Dashboard...
start http://localhost:3000

echo.
echo Nhấn phím bất kỳ để xem log hoạt động (hoặc đóng cửa sổ này)...
pause >nul
docker compose logs -f
