# 🐳 Hướng Dẫn Khởi Chạy SecNet Bằng Hoàn Toàn Docker Trên Windows

Tài liệu này hướng dẫn chi tiết từng bước cách cài đặt, đóng gói và khởi chạy toàn bộ hệ thống **Real-time Network Security Analytics & Alerting System (SecNet)** trên hệ điều hành **Windows 10 / 11** chỉ với **Docker Desktop**, không cần cài đặt Rust, Nix hay bất kỳ công cụ phát triển nào khác.

---

## 🏛️ 1. Kiến trúc Các Dịch vụ Trong Docker

Hệ thống được đóng gói thành **4 container độc lập**, tự động kết nối qua mạng nội bộ `secnet_mesh`:

| Container Name | Image / Base | Cổng Expose trên Windows | Chức năng chính |
|---|---|---|---|
| **`secnet_timescaledb`** | `timescale/timescaledb:latest-pg15` | `5432:5432` | Lưu trữ Time-series Hypertables (`traffic_events`), dữ liệu người dùng, cấu hình luật và nhật ký sự cố. Tự động nạp 11 migrations khi khởi tạo. |
| **`secnet_backend`** | `secnet-backend:latest` (Rust/Debian) | `8080:8080` | REST API Axum, WebSocket Hub (`/ws/alerts`, `/ws/traffic`), xác thực JWT Argon2id, hệ thống phát cảnh báo đa kênh. |
| **`secnet_frontend`** | `secnet-frontend:latest` (Nginx/WASM) | `3000:80` | Dashboard SOC hiện đại viết bằng Leptos 0.7 WebAssembly, Nginx reverse-proxy API & WebSockets. |
| **`secnet_capture_engine`**| `secnet-capture:latest` (Rust/Pcap) | *Nội bộ* | Bộ bắt gói tin & giả lập tấn công mạng thời gian thực (Port Scan, SYN Flood, Brute-force, ARP Spoof, DNS Tunneling, Z-Score Spike). |

---

## 💻 2. Yêu cầu Tiên Quyết Trên Windows

1. **Hệ điều hành**: Windows 10 (64-bit: Home/Pro/Enterprise build 19041+) hoặc Windows 11.
2. **Cài đặt Docker Desktop**:
   - Tải bộ cài chính thức tại: [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)
   - Trong quá trình cài đặt, tích chọn **"Use WSL 2 instead of Hyper-V (recommended)"**.
   - Khởi động lại máy tính nếu được yêu cầu.
   - Bật Docker Desktop và đợi đến khi biểu tượng cá voi ở góc thanh tác vụ chuyển sang màu xanh lá (*Engine running*).

---

## 🚀 3. Các Bước Khởi Chạy (1-Click / Terminal)

### Cách A: Khởi chạy nhanh bằng File Script `.bat` (Khuyên dùng)
Dự án đã tích hợp sẵn 2 file script tiện lợi cho Windows:
1. Nhấp đúp chuột vào file **`start_docker.bat`** để tự động kiểm tra Docker, copy file `.env` và build/khởi chạy toàn bộ hệ thống.
2. Để dừng hệ thống, nhấp đúp vào file **`stop_docker.bat`**.

---

### Cách B: Khởi chạy bằng PowerShell / Command Prompt (CMD)

#### Bước 1: Mở PowerShell hoặc Windows Terminal
Nhấn phím `Windows`, gõ `PowerShell`, chuột phải chọn **Run as Administrator** (hoặc mở Windows Terminal bình thường).

Di chuyển vào thư mục dự án:
```powershell
cd "D:\du-an\Real-time-Network-Security-Analytics-&-Alerting-System"
```
*(Thay đường dẫn trên bằng đường dẫn thực tế chứa thư mục dự án trên máy của bạn).*

#### Bước 2: Chuẩn bị file cấu hình môi trường `.env`
Sao chép file cấu hình mẫu:
```powershell
copy .env.example .env
```

#### Bước 3: Build và khởi chạy toàn bộ 4 dịch vụ
Chạy lệnh Docker Compose:
```powershell
docker compose up --build -d
```
> **Lưu ý:** Lần chạy đầu tiên, Docker sẽ tự động tải các base image và biên dịch Rust Release nhị phân tối ưu. Quá trình này diễn ra hoàn toàn tự động trong container.

#### Bước 4: Kiểm tra trạng thái hoạt động của các container
```powershell
docker compose ps
```
Kết quả hiển thị 4 container đều ở trạng thái `running` hoặc `healthy`:
```
NAME                    IMAGE                               COMMAND                  STATUS
secnet_timescaledb      timescale/timescaledb:latest-pg15   "docker-entrypoint.s…"   running (healthy)
secnet_backend          ...                                 "/app/backend"           running
secnet_frontend         ...                                 "nginx -g 'daemon of…"   running
secnet_capture_engine   ...                                 "/app/capture-engine"    running
```

---

## 🌐 4. Địa Chỉ Truy Cập & Đăng Nhập Hệ Thống

Mở bất kỳ trình duyệt nào trên Windows (Chrome, Edge, Firefox, Brave...):

| Thành phần | Đường dẫn (URL) | Ghi chú |
|---|---|---|
| **Web SOC Dashboard** | [http://localhost:3000](http://localhost:3000) | Giao diện giám sát (HTTP, chỉ truy cập từ chính máy chạy Docker) |
| **Web SOC Dashboard (TLS)** | [https://localhost](https://localhost) | Qua Nginx TLS, chứng chỉ tự ký — dùng khi truy cập từ máy khác |
| **Swagger UI (API Docs)**| [http://localhost:8080/swagger-ui](http://localhost:8080/swagger-ui) | Tài liệu REST API (tắt khi `ENVIRONMENT=production`, trừ khi `ENABLE_SWAGGER=true`) |
| **Prometheus Metrics** | [http://localhost:8080/metrics](http://localhost:8080/metrics) | Chỉ số giám sát (đặt `METRICS_TOKEN` để yêu cầu Bearer token) |

### 🔑 Tài khoản đăng nhập có sẵn:

| Vai trò | Tên đăng nhập (Username) | Mật khẩu (Password) | Quyền hạn |
|---|---|---|---|
| **Admin** | `admin` | `Admin@SecNet2026!` | Toàn quyền cấu hình luật, phân quyền, blocklist, kênh cảnh báo |
| **Analyst** | `analyst_linh` *(hoặc `analyst`)* | `Analyst@SecNet2026!` | Xử lý sự cố, xác nhận / đóng / mở lại cảnh báo, xem blocklist (chỉ Admin được chặn/bỏ chặn IP) |
| **Viewer** | `viewer_demo` *(hoặc `viewer`)* | `Viewer@SecNet2026!` | Xem báo cáo và biểu đồ giám sát (Read-only) |

---

## 🧪 5. Kiểm Thử Giả Lập Tấn Công (Demo Attack Scenarios)

Mặc định (`DEMO_SCENARIO=all`) capture-engine tự luân phiên đủ **8 kịch bản** tấn công, mỗi kịch bản cách nhau ~8 giây lưu lượng bình thường. Để chỉ chạy một kịch bản, đặt biến `DEMO_SCENARIO` rồi khởi động lại capture-engine:

```powershell
# 1. Giả lập tấn công Port Scan (Quét cổng hàng loạt)
docker exec -it -e DEMO_SCENARIO=port_scan secnet_capture_engine /app/capture-engine

# 2. Giả lập tấn công từ chối dịch vụ SYN Flood (DDoS)
docker exec -it -e DEMO_SCENARIO=syn_flood secnet_capture_engine /app/capture-engine

# 3. Giả lập tấn công dò mật khẩu SSH/RDP Brute-force
docker exec -it -e DEMO_SCENARIO=brute_force secnet_capture_engine /app/capture-engine

# 4. Giả lập tấn công giả mạo địa chỉ ARP Poisoning / Spoofing
docker exec -it -e DEMO_SCENARIO=arp_spoof secnet_capture_engine /app/capture-engine

# 5. Giả lập rò rỉ dữ liệu qua kênh ngầm DNS Tunneling
docker exec -it -e DEMO_SCENARIO=dns_tunneling secnet_capture_engine /app/capture-engine

# 6. Giả lập đột biến lưu lượng bất thường (Volume Anomaly Z-Score Spike)
docker exec -it -e DEMO_SCENARIO=volume_spike secnet_capture_engine /app/capture-engine

# 7. Giả lập ICMP Flood / Ping Flood
docker exec -it -e DEMO_SCENARIO=icmp_flood secnet_capture_engine /app/capture-engine

# 8. Giả lập C2 Beaconing (kết nối định kỳ ra máy chủ điều khiển)
docker exec -it -e DEMO_SCENARIO=beaconing secnet_capture_engine /app/capture-engine

# Cách gọn hơn: chạy lại container với một kịch bản cố định
$env:DEMO_SCENARIO="syn_flood"; docker compose up -d capture-engine
```

Quan sát trên Dashboard `http://localhost:3000`: Cảnh báo và chuông báo động sẽ lập tức kích hoạt, biểu đồ lưu lượng và bảng Incidents tự động cập nhật theo thời gian thực!

---

## 🛠️ 6. Các Lệnh Quản Lý Thường Dùng Trên Windows

- **Xem nhật ký hoạt động (Logs) của toàn hệ thống:**
  ```powershell
  docker compose logs -f
  ```
- **Xem nhật ký của riêng Backend:**
  ```powershell
  docker compose logs -f backend
  ```
- **Xem nhật ký của Capture Engine:**
  ```powershell
  docker compose logs -f capture-engine
  ```
- **Tạm dừng hệ thống:**
  ```powershell
  docker compose stop
  ```
- **Bật lại hệ thống sau khi dừng:**
  ```powershell
  docker compose start
  ```
- **Tắt và gỡ bỏ container:**
  ```powershell
  docker compose down
  ```
- **Xóa trắng cơ sở dữ liệu để chạy lại từ đầu:**
  ```powershell
  docker compose down -v
  docker compose up --build -d
  ```

---

## ❓ 7. Xử Lý Các Vấn Đề Thường Gặp Trên Windows (Troubleshooting)

### Vấn đề 1: "error during connect: This error may indicate that the docker daemon is not running"
- **Nguyên nhân**: Ứng dụng Docker Desktop chưa được mở hoặc đang trong quá trình khởi động.
- **Cách xử lý**: Mở Docker Desktop từ Start Menu, chờ biểu tượng chuyển sang trạng thái "Engine running", sau đó chạy lại lệnh.

### Vấn đề 2: Lỗi trùng cổng (Port already in use: 5432 hoặc 8080 hoặc 3000)
- **Nguyên nhân**: Trên máy Windows của bạn đã cài sẵn PostgreSQL (thường chiếm cổng 5432) hoặc có ứng dụng web khác đang chiếm cổng 8080/3000.
- **Cách xử lý**:
  1. Mở file `.env`.
  2. Đổi cổng sang cổng khác, ví dụ:
     ```env
     POSTGRES_PORT=5433
     SERVER_PORT=8081
     ```
  3. Trong `docker-compose.yml`, cập nhật port tương ứng hoặc tắt dịch vụ PostgreSQL cục bộ trên Windows Services (`services.msc` -> tìm `postgresql-x64` -> nhấn *Stop*).

### Vấn đề 3: Lỗi ký tự kết thúc dòng CRLF khi clone git trên Windows
- **Nguyên nhân**: Windows tự động chuyển dấu xuống dòng `LF` thành `CRLF`, có thể gây lỗi cú pháp trong script Linux container.
- **Cách xử lý**: Cấu hình Git giữ nguyên định dạng `LF`:
  ```powershell
  git config --global core.autocrlf input
  ```

### Vấn đề 4: Docker Desktop chiếm nhiều dung lượng RAM (Vmmem)
- **Cách xử lý**: Bạn có thể giới hạn tài nguyên cho WSL2 bằng cách tạo file `C:\Users\<Tên_User>\.wslconfig` với nội dung:
  ```ini
  [wsl2]
  memory=4GB
  processors=4
  ```
  Sau đó mở PowerShell chạy: `wsl --shutdown` và mở lại Docker Desktop.
