# 🐳 Hướng Dẫn Khởi Chạy SecNet Bằng Docker Trên Windows

Tài liệu này hướng dẫn từng bước cài đặt và chạy toàn bộ hệ thống **Real-time Network Security Analytics & Alerting System (SecNet)** trên **Windows 10 / 11** chỉ với **Docker Desktop**. Không cần cài Rust, Nix, Trunk hay PostgreSQL. Toàn bộ mã nguồn được biên dịch bên trong container.

> Người dùng NixOS / Linux xem mục **7. Hướng dẫn Khởi chạy** trong [`README.md`](README.md).

---

## 🏛️ 1. Các Dịch Vụ Trong Docker

`docker compose` khởi động **6 container**, kết nối với nhau qua mạng nội bộ `secnet_mesh`:

| Container | Image / Nền tảng | Cổng trên Windows | Chức năng |
|---|---|---|---|
| **`secnet_timescaledb`** | `timescale/timescaledb:2.14.2-pg15` | `127.0.0.1:5432` | PostgreSQL 15 + TimescaleDB: hypertable `traffic_events`, người dùng, luật, cảnh báo, audit log |
| **`secnet_redis`** | `redis:7-alpine` | `127.0.0.1:6379` | Cache và chống bão cảnh báo (throttling) |
| **`secnet_backend`** | Rust (Axum) | `127.0.0.1:8080` | REST API, WebSocket (`/ws/alerts`, `/ws/traffic`), JWT + Argon2id, gửi cảnh báo đa kênh. **Tự chạy 16 migration** (kèm dữ liệu mẫu và tài khoản đăng nhập) khi khởi động |
| **`secnet_frontend`** | Nginx + Leptos WASM | `127.0.0.1:3000` | Giao diện SOC Dashboard |
| **`secnet_nginx_tls`** | `nginx:alpine` | `80`, `443` | Reverse proxy HTTPS. Tự sinh chứng chỉ tự ký lần đầu. Cổng 80 tự chuyển sang 443 |
| **`secnet_capture_engine`** | Rust (pnet/pcap) | *nội bộ* | Bắt gói tin / giả lập 8 kịch bản tấn công, chạy luật phát hiện theo MITRE ATT&CK |

Các cổng có tiền tố `127.0.0.1` chỉ truy cập được từ chính máy Windows đó. Máy khác trong mạng LAN truy cập qua `https://<IP-máy-Windows>`.

---

## 💻 2. Chuẩn Bị Trên Windows

### 2.1. Yêu cầu hệ thống

- Windows 10 64-bit (build 19041 trở lên) hoặc Windows 11.
- RAM tối thiểu 8 GB (khuyến nghị 16 GB). Lần build đầu dùng nhiều RAM để biên dịch Rust.
- Ổ đĩa còn trống khoảng 15 GB.
- Bật ảo hoá (Virtualization) trong BIOS. Kiểm tra: **Task Manager → Performance → CPU → Virtualization: Enabled**.

### 2.2. Cài WSL 2

Mở **PowerShell (Run as Administrator)** và chạy:

```powershell
wsl --install
```

Khởi động lại máy khi được yêu cầu. Nếu WSL đã có sẵn, cập nhật bằng:

```powershell
wsl --update
```

### 2.3. Cài Docker Desktop

1. Tải tại https://www.docker.com/products/docker-desktop/
2. Khi cài, tích chọn **"Use WSL 2 instead of Hyper-V (recommended)"**.
3. Khởi động lại máy nếu được yêu cầu.
4. Mở Docker Desktop, chấp nhận điều khoản, đợi góc dưới bên trái hiện **"Engine running"** (màu xanh).
5. Kiểm tra trong PowerShell:
   ```powershell
   docker version
   docker compose version
   ```
   Lệnh đầu phải hiện cả phần **Client** và **Server**.

### 2.4. Cài Git và lấy mã nguồn

1. Tải Git tại https://git-scm.com/download/win và cài với tuỳ chọn mặc định.
2. **Trước khi clone**, cấu hình Git giữ nguyên ký tự xuống dòng `LF` (tránh lỗi script shell trong container):
   ```powershell
   git config --global core.autocrlf input
   ```
3. Clone dự án vào thư mục **không có dấu tiếng Việt và khoảng trắng**, ví dụ `D:\projects`:
   ```powershell
   cd D:\projects
   git clone <url-repo> Real-time-Network-Security-Analytics-Alerting-System
   cd Real-time-Network-Security-Analytics-Alerting-System
   ```

---

## 🚀 3. Khởi Chạy Hệ Thống

### Cách A: Dùng file `.bat` (nhanh nhất)

1. Mở thư mục dự án trong File Explorer.
2. Nhấp đúp **`start_docker.bat`**. Script sẽ:
   - kiểm tra Docker đã cài và đang chạy,
   - tạo file `.env` từ `.env.example` nếu chưa có,
   - chạy `docker compose up --build -d`,
   - mở trình duyệt tới http://localhost:3000,
   - bấm phím bất kỳ để xem log trực tiếp (đóng cửa sổ log không làm dừng hệ thống).
3. Để kiểm tra mọi tính năng đã hoạt động, nhấp đúp **`test.bat`** (xem mục 7).
4. Để dừng và xoá container (vẫn giữ dữ liệu), nhấp đúp **`stop_docker.bat`**.

### Cách B: Dùng PowerShell / Windows Terminal

#### Bước 1: Mở PowerShell tại thư mục dự án

```powershell
cd D:\projects\Real-time-Network-Security-Analytics-Alerting-System
```

#### Bước 2: Tạo file cấu hình `.env` (tuỳ chọn)

```powershell
copy .env.example .env
```

Không có `.env` thì `docker-compose.yml` dùng giá trị mặc định. Các biến quan trọng:

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `postgres` / `postgres` / `network_security` | Tài khoản CSDL |
| `POSTGRES_PORT` | `5432` | Cổng CSDL trên Windows (đổi nếu máy đã cài PostgreSQL) |
| `REDIS_PORT` | `6379` | Cổng Redis trên Windows |
| `REDIS_PASSWORD` | `secnet_redis_dev_password` | Mật khẩu Redis |
| `JWT_SECRET` | chuỗi dev | **Bắt buộc đổi khi `ENVIRONMENT=production`** |
| `SIMULATION_MODE` | `true` | Sinh lưu lượng giả lập (nên giữ `true` trên Windows) |
| `DEMO_SCENARIO` | `all` | Kịch bản tấn công giả lập (xem mục 6) |

> Các biến `SMTP_*`, `TELEGRAM_*`, `WEBHOOK_DEFAULT_URL` trong `.env.example` **không được dùng**. Kênh thông báo được cấu hình trên giao diện web (xem mục 5).

#### Bước 3: Build và chạy

```powershell
docker compose up --build -d
```

Lần đầu mất khoảng **10–20 phút** (tải image + biên dịch Rust release). Các lần sau chỉ vài giây nhờ cache.

#### Bước 4: Kiểm tra trạng thái

```powershell
docker compose ps
```

Kết quả mong đợi (6 container đều `Up`):

```
NAME                    STATUS
secnet_backend          Up (healthy)
secnet_capture_engine   Up
secnet_frontend         Up (healthy)
secnet_nginx_tls        Up
secnet_redis            Up (healthy)
secnet_timescaledb      Up (healthy)
```

Kiểm tra API:

```powershell
curl.exe http://127.0.0.1:8080/health
# {"service":"secnet-backend","status":"ok"}
```

---

## 🌐 4. Truy Cập Web & Tài Khoản Đăng Nhập

### 4.1. Địa chỉ truy cập

| Thành phần | URL | Ghi chú |
|---|---|---|
| **Dashboard (HTTP)** | http://localhost:3000 | Dễ dùng nhất, chỉ từ chính máy Windows |
| **Dashboard (HTTPS)** | https://localhost | Qua Nginx TLS. Máy khác trong LAN dùng `https://<IP-máy-Windows>` |
| **Swagger UI** | http://localhost:8080/swagger-ui/ | Tài liệu REST API |
| **Prometheus metrics** | http://localhost:8080/metrics | Chỉ số giám sát |

Khi mở HTTPS, trình duyệt cảnh báo vì chứng chỉ tự ký:
- **Chrome / Edge:** bấm **Advanced → Continue to localhost (unsafe)**.
- **Firefox:** bấm **Advanced… → Accept the Risk and Continue**.

### 4.2. 🔑 Tài khoản đăng nhập web

| Vai trò | Username | Mật khẩu | Quyền hạn |
|---|---|---|---|
| **Admin** | `admin` | `Admin@SecNet2026!` | Toàn quyền: luật phát hiện, kênh thông báo, chặn/bỏ chặn IP, audit log |
| **Analyst** | `analyst` hoặc `analyst_linh` | `Analyst@SecNet2026!` | Xác nhận / đóng / mở lại sự cố, xem blocklist (chỉ đọc) |
| **Viewer** | `viewer` hoặc `viewer_demo` | `Viewer@SecNet2026!` | Chỉ xem dashboard và báo cáo |

Tài khoản tự đăng ký trên trang web luôn có vai trò `Viewer`.

### 4.3. 🔑 Tài khoản CSDL & Redis

| Dịch vụ | Thông tin kết nối |
|---|---|
| **PostgreSQL** | Host `localhost`, Port `5432`, User `postgres`, Password `postgres`, Database `network_security` |
| Chuỗi kết nối | `postgres://postgres:postgres@localhost:5432/network_security` |
| Mở psql trong container | `docker exec -it secnet_timescaledb psql -U postgres -d network_security` |
| **Redis** | Host `localhost`, Port `6379`, Password `secnet_redis_dev_password` |

Có thể kết nối PostgreSQL bằng DBeaver hoặc pgAdmin với thông tin trên.

> ⚠️ Các mật khẩu trên chỉ dùng cho dev/demo. Khi triển khai thật, đổi mật khẩu tài khoản web, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET` và đặt `ENVIRONMENT=production` trong `.env`.

---

## 📧 5. Cấu Hình Gửi Cảnh Báo Qua Email (Gmail)

### 5.1. Tạo App Password cho Gmail

1. Đăng nhập Gmail dùng để **gửi** cảnh báo.
2. Bật **Xác minh 2 bước** tại https://myaccount.google.com/security
3. Vào https://myaccount.google.com/apppasswords, đặt tên (ví dụ `SecNet`) và bấm **Create**.
4. Sao chép mã **16 ký tự** Google hiển thị. Mã chỉ hiện một lần.

### 5.2. Tạo kênh Email trên web

Đăng nhập `admin`, vào mục **Alert channels** ở thanh bên trái, bấm **Add channel**, chọn Channel type **Email (SMTP)** và điền:

| Ô | Giá trị |
|---|---|
| Channel name | tên tuỳ ý, ví dụ `gmail-soc` |
| SMTP Host | `smtp.gmail.com` |
| Port | `587` |
| Connection security | `STARTTLS (587/2525)` |
| Username | Địa chỉ Gmail gửi, đầy đủ, ví dụ `ten.cua.ban@gmail.com` |
| Password | App Password 16 ký tự, viết liền không khoảng trắng (**không** phải mật khẩu Gmail) |
| From address | Để trống (hệ thống tự dùng Username) |
| Recipient Email (To) | Hộp thư nhận cảnh báo. Mỗi kênh một địa chỉ; muốn gửi nhiều nơi thì tạo nhiều kênh |
| Minimum Severity | Mức cảnh báo tối thiểu để gửi |

Bấm **Save channel**, rồi bấm **Send test alert** trên kênh vừa tạo và kiểm tra hộp thư (kể cả thư mục Spam).

Dùng Outlook/Hotmail: SMTP Host `smtp-mail.outlook.com`, Port `587`, `STARTTLS`.

### 5.3. Lỗi thường gặp khi gửi email

Xem log: `docker compose logs -f backend`

| Lỗi | Nguyên nhân | Cách xử lý |
|---|---|---|
| `530 5.7.1 Authentication required` | Kênh chưa có Username/Password | Tạo lại kênh, điền đủ Username và App Password |
| `535 5.7.8 Username and Password not accepted` | Sai App Password hoặc dùng mật khẩu Gmail thường | Tạo App Password mới |
| `Connection timed out` | Mạng/tường lửa chặn cổng 587 | Kiểm tra antivirus / tường lửa công ty |

Giao diện chưa có chức năng sửa kênh. Muốn đổi cấu hình thì xoá kênh rồi tạo lại.

---

## 🧪 6. Chọn Kịch Bản Tấn Công Giả Lập

Mặc định (`DEMO_SCENARIO=all`) capture-engine luân phiên đủ **8 kịch bản**, xen giữa bởi khoảng 8 giây lưu lượng bình thường. Để chạy một kịch bản cố định, trong PowerShell:

```powershell
$env:DEMO_SCENARIO="syn_flood"; docker compose up -d capture-engine
```

Quay lại chế độ luân phiên:

```powershell
$env:DEMO_SCENARIO="all"; docker compose up -d capture-engine
```

Hoặc sửa `DEMO_SCENARIO=...` trong `.env` rồi chạy `docker compose up -d capture-engine`.

| Giá trị | Kịch bản | MITRE ATT&CK |
|---|---|---|
| `port_scan` | Quét cổng hàng loạt | T1046 |
| `syn_flood` | SYN Flood / DDoS | T1498 |
| `brute_force` | Dò mật khẩu SSH/RDP | T1110 |
| `arp_spoof` | Giả mạo ARP | T1557 |
| `dns_tunneling` | Rò rỉ dữ liệu qua DNS | T1071.004 |
| `volume_spike` | Đột biến lưu lượng (Z-Score) | T1020 |
| `icmp_flood` | ICMP / Ping Flood | T1498.001 |
| `beaconing` | C2 Beaconing | T1071 |
| `all` | Luân phiên cả 8 kịch bản | |
| `none` | Chỉ lưu lượng bình thường | |

Theo dõi trên Dashboard: cảnh báo, chuông báo động, biểu đồ lưu lượng và bảng Incidents cập nhật theo thời gian thực.

---

## ✅ 7. Kiểm Thử Toàn Bộ Tính Năng (`test.bat`)

Sau khi hệ thống đã chạy (mục 3), nhấp đúp **`test.bat`** hoặc chạy trong CMD/PowerShell tại thư mục dự án:

| Lệnh | Thời gian | Nội dung |
|---|---|---|
| `test.bat` | ~1 phút | Kiểm thử nhanh toàn bộ tính năng qua hệ thống đang chạy (bảng bên dưới) |
| `test.bat notify` | ~1 phút | Như trên, **gửi thật** "test alert" qua mọi kênh thông báo đang bật (Email, Telegram, Slack, Webhook) |
| `test.bat full` | 10–20 phút lần đầu | Như trên, chạy thêm bộ test Rust `cargo test --workspace` (unit, tích hợp, benchmark) trong container `rust:bookworm` |
| `test.bat all` | | `notify` + `full` |

Các nhóm kiểm thử:

| # | Nhóm | Kiểm tra |
|---|---|---|
| 1 | Docker | Docker chạy, đủ 6 container ở trạng thái `running` / `healthy` |
| 2 | Hạ tầng | `/health`, frontend `:3000`, proxy `/api`, chuyển hướng `:80 → 443`, HTTPS `:443`, Swagger, OpenAPI, `/metrics` |
| 3 | CSDL | Đủ migration, `traffic_events` là hypertable, có 5 tài khoản mẫu và 8 luật, Redis trả `PONG` |
| 4 | Xác thực | Đăng nhập 3 vai trò, sai mật khẩu, thiếu/giả token, refresh token (dùng 1 lần), đăng xuất thu hồi token, đăng ký luôn là `viewer` |
| 5 | Dữ liệu | Dashboard, traffic (lọc giao thức), alerts (lọc mức độ, chi tiết, Inspect), nhãn MITRE, devices, sensor, rules, audit log, blocklist, xuất CSV |
| 6 | Realtime | Lưu lượng mới được ghi, có cảnh báo trong 15 phút, WebSocket `/ws/traffic` và `/ws/alerts` (trực tiếp và qua proxy), từ chối token sai |
| 7 | RBAC | Viewer/Analyst không xem audit log, không tạo luật, không chặn IP, không tạo kênh; Viewer không xử lý sự cố |
| 8 | Sự cố | Analyst acknowledge → resolve, Admin reopen |
| 9 | Luật | Tạo, đọc, sửa, từ chối trùng tên / không hợp lệ, xoá, audit log ghi nhận |
| 10 | Blocklist | Chặn / bỏ chặn IP, từ chối IP sai định dạng và loopback |
| 11 | Thông báo | Chống SSRF, tạo/sửa/xoá kênh, ẩn bí mật với non-admin, kênh email có đủ tài khoản SMTP, (tuỳ chọn) gửi thật |
| 12 | Rust | `cargo test --workspace` với CSDL riêng `secnet_test` (tạo rồi xoá, không đụng dữ liệu đang chạy) |

Kết quả từng mục hiện màu: **PASS** (đạt), **FAIL** (lỗi, kèm lý do), **WARN** (cần để ý), **SKIP** (bỏ qua). Báo cáo được lưu vào `test_report.txt`. Mọi dữ liệu test tạo ra (luật, IP chặn, kênh, tài khoản) đều được xoá sau khi chạy.

Lưu ý:
- Mỗi lượt test gọi đăng nhập/đăng ký 5 lần. Backend giới hạn 10 lần mỗi phút, nên nếu chạy liên tiếp nhiều lần, script sẽ tự chờ 60 giây rồi thử lại.
- Mục 8 chuyển một cảnh báo đang mở qua acknowledged → resolved rồi mở lại, nên cảnh báo đó trở về trạng thái `open` như ban đầu.
- Script chính nằm ở `scripts\test_system.ps1`. Có thể chạy trực tiếp: `powershell -ExecutionPolicy Bypass -File scripts\test_system.ps1 -Full -SendNotifications`.

---

## 🛠️ 8. Các Lệnh Quản Lý Thường Dùng

```powershell
docker compose logs -f                   # log toàn hệ thống (Ctrl+C để thoát)
docker compose logs -f backend           # log backend (lỗi gửi email, API)
docker compose logs -f capture-engine    # log bắt gói / phát hiện tấn công
docker compose restart backend           # khởi động lại một dịch vụ
docker compose up -d --build             # build lại sau khi cập nhật mã nguồn (git pull)
docker compose stop                      # tạm dừng, giữ nguyên container và dữ liệu
docker compose start                     # chạy lại sau khi stop
docker compose down                      # xoá container, GIỮ dữ liệu CSDL
docker compose down -v                   # xoá cả CSDL; lần chạy sau nạp lại dữ liệu mẫu và tài khoản mặc định
```

Cập nhật lên phiên bản mới:

```powershell
git pull
docker compose up -d --build
```

---

## ❓ 9. Xử Lý Sự Cố Trên Windows

### Vấn đề 1: `error during connect ... the docker daemon is not running`
- **Nguyên nhân:** Docker Desktop chưa mở hoặc đang khởi động.
- **Cách xử lý:** Mở Docker Desktop, đợi **"Engine running"** rồi chạy lại lệnh.

### Vấn đề 2: `port is already allocated` / `Ports are not available`
- **5432:** Máy đã cài PostgreSQL. Tắt service `postgresql-x64-*` trong `services.msc`, hoặc đặt `POSTGRES_PORT=5433` trong `.env`.
- **6379:** Đặt `REDIS_PORT=6380` trong `.env`.
- **80 / 443:** Thường do IIS, Skype hoặc XAMPP/Apache. Tắt IIS: `net stop w3svc` (PowerShell Admin), hoặc tắt Apache trong XAMPP.
- **8080 / 3000:** Tìm tiến trình chiếm cổng rồi tắt nó:
  ```powershell
  netstat -ano | findstr :8080
  taskkill /PID <PID> /F
  ```

Sau khi đổi, chạy lại `docker compose up -d`.

### Vấn đề 3: Container `secnet_nginx_tls` báo lỗi `/entrypoint.sh: not found` hoặc `\r`
- **Nguyên nhân:** Git đã chuyển `LF` thành `CRLF` khi clone.
- **Cách xử lý:**
  ```powershell
  git config --global core.autocrlf input
  git rm --cached -r .
  git reset --hard
  docker compose up -d --build
  ```

### Vấn đề 4: Build bị dừng với lỗi `killed` / `signal: 9` / hết bộ nhớ
- **Nguyên nhân:** WSL 2 thiếu RAM khi biên dịch Rust.
- **Cách xử lý:** Tạo file `C:\Users\<Tên_User>\.wslconfig`:
  ```ini
  [wsl2]
  memory=6GB
  processors=4
  swap=4GB
  ```
  Chạy `wsl --shutdown`, mở lại Docker Desktop và build lại.

### Vấn đề 5: Docker Desktop chiếm nhiều RAM (tiến trình `Vmmem`) khi không dùng
- Chạy `docker compose stop` hoặc giới hạn RAM như Vấn đề 4.

### Vấn đề 6: Đăng nhập báo sai mật khẩu với tài khoản mặc định
- Kiểm tra đúng chữ hoa và ký tự `@`, `!`: `Admin@SecNet2026!`.
- Nếu CSDL cũ đã bị sửa, reset về dữ liệu mẫu (**mất toàn bộ dữ liệu**):
  ```powershell
  docker compose down -v
  docker compose up -d --build
  ```

### Vấn đề 7: Máy khác trong LAN không vào được `https://<IP-máy-Windows>`
- Mở cổng trong Windows Defender Firewall (PowerShell Admin):
  ```powershell
  New-NetFirewallRule -DisplayName "SecNet HTTPS" -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow
  ```
- Xem IP máy bằng `ipconfig` (dòng IPv4 Address).

### Vấn đề 8: Giao diện không đổi sau khi build lại
- Tải lại trang bỏ cache: `Ctrl + Shift + R` (hoặc `Ctrl + F5`).
