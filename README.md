# 🛡️ Real-time Network Security Analytics & Alerting System (SecNet)

Hệ thống giám sát và phân tích lưu lượng mạng theo thời gian thực (NIDS/NIPS), tự động phát hiện hành vi xâm nhập và tấn công mạng theo chuẩn **MITRE ATT&CK**, lưu trữ chuỗi thời gian trên TimescaleDB hypertable, phát cảnh báo đa kênh (Email, Webhook, Telegram, Slack) và điều khiển tường lửa ngăn chặn kẻ tấn công.

---

## 🏛️ 1. Kiến trúc Hệ thống & Luồng Dữ liệu (End-to-End Pipeline)

Hệ thống được thiết kế theo kiến trúc phân tán 4 tầng, module hóa bằng Rust Cargo Workspace, bảo đảm an toàn bộ nhớ (memory safety), hiệu năng xử lý cao (> 10,000 packets/giây) và phân tách ranh giới tin cậy rõ ràng:

```mermaid
flowchart TD
    subgraph Untrusted_Zone ["Untrusted Network / Ingestion Zone"]
        Net[Network Interface / Raw Sockets]
        Sim[Traffic Simulator: 8 Attack Scenarios]
    end

    subgraph Core_Engine ["Capture Engine (Rust Tokio Runtime)"]
        Capture[Live Capture: pnet / pcap / ARP / DNS]
        TrafficBuf[Async MPSC Channel: 5000 events]
        BatchPersist[Batch Persister: 100 pkts / 500ms]
        
        subgraph Detection_Pipeline ["8 Detection Rules (MITRE ATT&CK)"]
            R1["Port Scan (T1046)"]
            R2["SYN Flood / DDoS (T1498)"]
            R3["SSH/RDP Brute-Force (T1110)"]
            R4["ARP Spoofing / Poisoning (T1557)"]
            R5["DNS Tunneling / Entropy (T1071.004)"]
            R6["Traffic Volume Anomaly (T1020)"]
            R7["ICMP Flood / Smurf (T1498.001)"]
            R8["C2 Beaconing Callback (T1071)"]
        end

        StateSnap[Atomic State Persistence & Auto-Cleanup]
        AutoIPS[Auto-Response IPS: nftables / iptables / Blocklist]
        SensorHB[Sensor Heartbeat Monitor: 15s interval]
    end

    subgraph Data_Storage ["Data Persistence (TimescaleDB / PostgreSQL 15+)"]
        DB_Hyper[(traffic_events: HYPERTABLE)]
        DB_Alerts[(alerts table)]
        DB_Rules[(detection_rules)]
        DB_Audit[(audit_logs & sensor_heartbeats)]
        DB_Block[(blocked_ips)]
        PG_Notify["PostgreSQL LISTEN / NOTIFY Trigger"]
    end

    subgraph API_Alerting ["Backend API & Dispatcher (Axum)"]
        API[Axum REST API / Swagger UI]
        PgListener[PgListener: new_alert & new_traffic]
        WS[Authenticated WebSocket Hub: /ws/alerts, /ws/traffic]
        Dispatcher[Multi-channel Alert Dispatcher]
        Throttler[Alert Throttler: DashMap Cooldown]
    end

    subgraph Notification_Channels ["External Notification Sinks"]
        Email[Email / SMTP Transport TLS]
        TG[Telegram Bot API: HTML parse_mode]
        Slack[Slack Incoming Webhook: Block Kit]
        Hook[SIEM / Incident Webhook: SSRF-protected]
    end

    subgraph Presentation_Layer ["Presentation Layer (Client Browser)"]
        UI[Leptos 0.7 WASM Dark-Mode Web Dashboard]
    end

    Net -->|Raw Ethernet Frames| Capture
    Sim -->|Simulated Events| Capture
    Capture -->|TrafficEvents| TrafficBuf
    TrafficBuf --> Detection_Pipeline
    TrafficBuf --> BatchPersist
    BatchPersist -->|Batch Insert + pg_notify| DB_Hyper

    Detection_Pipeline -->|Trigger Alert| AutoIPS
    Detection_Pipeline -->|INSERT Alert| DB_Alerts
    DB_Alerts -->|Trigger new_alert| PG_Notify
    DB_Rules -->|Trigger rules_changed| PG_Notify

    PG_Notify -->|Async Listen| PgListener
    PG_Notify -.->|Hot Reload Rules| Core_Engine
    PgListener --> WS
    PgListener --> Throttler
    Throttler --> Dispatcher

    Dispatcher --> Email
    Dispatcher --> TG
    Dispatcher --> Slack
    Dispatcher --> Hook

    WS -->|WSS Stream| UI
    UI -->|REST Queries / Bearer JWT| API
    API -->|Queries| Data_Storage
```

### Ranh giới tin cậy & Biện pháp Bảo vệ (Zero Trust Boundaries):
1. **Raw Network Interface vs Capture Engine:** Parser giải mã an toàn bộ nhớ qua `pnet`, kiểm tra bounds, loại trừ traffic quản trị của chính hệ thống (DB 5432, Redis 6379, API 8080) nhằm triệt tiêu vòng lặp phản hồi dữ liệu (feedback loop).
2. **Auto-Response Allowlist:** Tránh tự động chặn Gateway, DNS resolver, loopback (`ALLOWLIST_IPS`) khi phát hiện tấn công.
3. **Backend API vs Client Browser:** Xác thực bắt buộc bằng JWT (chu kỳ 24h, kèm refresh token), băm mật khẩu Argon2id. Phân quyền RBAC 3 vai trò (`Admin`, `Analyst`, `Viewer`) enforce ở phía server với nguyên tắc *deny by default*.
4. **WebSocket Security:** Bắt buộc truyền JWT token hợp lệ qua query param `?token=` khi thiết lập kết nối WebSocket handshake; từ chối và ngắt kết nối ngay lập tức nếu token hết hạn hoặc giả mạo.
5. **SSRF & Notification Protection:** Bộ lọc IP riêng tư/nội bộ (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`) chặn đứng các cuộc tấn công SSRF từ cấu hình Webhook.
6. **Rate Limiting & Anti-Spoofing:** Rate limit bảo vệ các endpoint xác thực (10 req/phút) và API chung (200 req/phút), phân tích đúng client IP qua `X-Real-IP` hoặc hop cuối cùng của `X-Forwarded-For`.

---

## 📁 2. Cấu trúc Thư mục Cargo Workspace

```
.
├── Cargo.toml                     # Root Cargo Workspace (4 crates)
├── flake.nix                      # Nix Flake môi trường chuẩn (Rust, SQLx, Trunk, Libpcap)
├── docker-compose.yml             # Docker compose (TimescaleDB, Redis, Backend, Frontend, Nginx)
├── .env.example                   # Biến môi trường mẫu
├── scripts/
│   └── backup_db.sh               # Tự động sao lưu & phục hồi CSDL định kỳ (Disaster Recovery)
├── migrations/                    # Bộ 15 migration SQLx chuẩn TimescaleDB
│   ├── 20260101000001_init_extensions_and_enums.sql
│   ├── 20260101000002_create_users_table.sql
│   ├── 20260101000003_create_devices_table.sql
│   ├── 20260101000004_create_detection_rules_table.sql
│   ├── 20260101000005_create_traffic_events_hypertable.sql
│   ├── 20260101000006_create_alerts_table.sql
│   ├── 20260101000007_create_notification_channels_table.sql
│   ├── 20260101000008_create_audit_logs_table.sql
│   ├── 20260101000009_create_blocked_ips_table.sql
│   ├── 20260101000010_create_indexes_and_constraints.sql
│   ├── 20260101000011_seed_sample_data.sql
│   ├── 20260101000012_hypertable_compression_retention_and_cagg.sql
│   ├── 20260101000013_notify_new_alert_trigger.sql
│   ├── 20260101000014_notify_rules_changed_trigger.sql
│   └── 20260101000015_add_mitre_and_heartbeat.sql
└── crates/
    ├── common/                    # Crate dùng chung (Models, DTOs, Enums, Sensor, Audit)
    ├── capture-engine/            # Live capture sniffer, 8 detection rules, simulator, benchmark
    ├── backend/                   # REST API Axum, WebSocket, RBAC, Dispatcher, Audit, Sensor
    └── frontend/                  # Leptos 0.7 WASM Web Dashboard (Dark Mode, SVG Charts, Live SOC)
```

---

## ⚙️ 3. Danh mục 8 Quy tắc Phát hiện Xâm nhập & MITRE ATT&CK Matrix

| # | Tên Quy tắc | Kỹ thuật MITRE | Độ nghiêm trọng | Thuật toán & Cơ chế phát hiện |
|---|---|---|---|---|
| **1** | **Port Scan Detection** | Discovery (`T1046`) | High | Theo dõi số lượng cổng đích phân biệt trên 1 cặp IP trong cửa sổ trượt $O(1)$. Chỉ tính gói TCP SYN (loại trừ phản hồi server trên cổng tạm thời). Ngưỡng mặc định: > 15 cổng / 10s. |
| **2** | **SYN Flood / DDoS** | Impact (`T1498`) | Critical | Đếm số lượng gói tin mang cờ `SYN` (không kèm `ACK`) nhắm vào mục tiêu trong 5 giây. Ngưỡng mặc định: > 200 pkts / 5s. Xác định nguồn chiếm ưu thế (≥ 50% số SYN); chỉ khi đó mới tự động đưa IP nguồn vào blocklist 2 giờ — flood phân tán/giả mạo nguồn không bị auto-block. |
| **3** | **SSH/RDP Brute-Force** | Credential Access (`T1110`) | High | Giám sát kết nối dồn dập vào cổng xác thực nhạy cảm (21, 22, 23, 3389, 5432, 3306). Chỉ đếm gói SYN khởi tạo hoặc RST (kết nối thất bại), triệt tiêu báo nhầm từ việc gõ phím SSH thông thường. |
| **4** | **ARP Spoofing / Poisoning** | Credential Access (`T1557`) | Critical | Duy trì bảng ánh xạ *IP người gửi → MAC người gửi* từ gói ARP. Cảnh báo khi một gói ARP khẳng định IP đã biết nằm ở MAC khác. Giữ MAC tin cậy (không flapping); chấp nhận MAC mới nếu MAC cũ im lặng > 1 giờ. IP trong cảnh báo là nạn nhân nên không bao giờ bị auto-block. |
| **5** | **DNS Tunneling Detection** | Exfiltration (`T1071.004`) | Medium / High | Phân tích QNAME từ gói tin DNS UDP/53. Tính Shannon Entropy $H(X) = -\sum P(x)\log_2 P(x)$ trên nhãn dài nhất bên trái domain gốc. Ngưỡng entropy ≥ 3.8 với nhãn ≥ 30 ký tự; chống lặp theo (IP nguồn, domain gốc) trong 60 giây. |
| **6** | **Traffic Volume Anomaly** | Exfiltration (`T1020`) | Medium | Gom tổng byte theo từng giây; so sánh giây vừa kết thúc với baseline cửa sổ trượt *và* EWMA (chỉ từ các giây trước): $Z = \frac{x - \mu}{\sigma} \ge 3.0$. Một gói lớn đơn lẻ không còn gây báo động. |
| **7** | **ICMP Flood / Smurf** | Impact (`T1498.001`) | High | Đếm lưu lượng ICMP/ICMPv6 dồn dập vượt ngưỡng (mặc định > 50 pkts / 5s) nhắm tới một địa chỉ đích, phát hiện sớm các đợt Ping Flood hoặc Smurf DDoS. |
| **8** | **C2 Beaconing Callback** | Command & Control (`T1071`) | High | Phân tích chuỗi khoảng thời gian $(\Delta t)$ giữa các kết nối ra ngoài liên tiếp. Tính hệ số biến thiên $CV = \frac{\sigma}{\mu}$. Cảnh báo khi $CV \le 0.15$ (chu kỳ rất đều, jitter cực thấp đặc trưng của mã độc C2). |

---

## 🔔 4. Hệ thống Cảnh báo Đa kênh (Multi-Channel Alerting)

1. **Email Sink (`lettre`):** STARTTLS (mặc định, cổng 587/2525), TLS (465) hoặc không mã hoá cho relay nội bộ (`smtp_security`); không bao giờ gửi mật khẩu qua kết nối không mã hoá. Nội dung dạng văn bản thuần.
2. **Telegram Bot Sink (`reqwest`):** Sử dụng định dạng `HTML` an toàn (tránh lỗi cú pháp markdown khi gặp ký tự lạ), kèm icon mức độ nghiêm trọng và nút bấm trực tiếp.
3. **Slack Incoming Webhook:** Định dạng JSON Block Kit chuẩn (`text` và `blocks`), tương thích hoàn toàn với Slack Apps và Incoming Webhooks.
4. **Custom SIEM Webhook:** Payload JSON của alert qua HTTPS; chống SSRF (chặn dải IP nội bộ, không theo redirect, ghim IP đã kiểm tra để chống DNS rebinding).
5. **Cơ chế Chống bão cảnh báo (Alert Throttling):** Cooldown 60 giây (`ALERT_DEDUPLICATION_WINDOW_SECONDS`) theo khóa `(rule_id, src_ip)` (hoặc tiêu đề alert nếu không có rule), phân tán qua Redis khi có.
6. **Kiểm tra kênh:** Nút "Send test alert" hiển thị lý do lỗi cụ thể (SMTP, HTTP status…). Kênh mẫu trong seed bị tắt sẵn cho tới khi admin cấu hình thật.

---

## 💻 5. Giao diện SOC Dashboard & Trải nghiệm Người dùng (Frontend)

- **Live Throughput Chart:** Đo lường chính xác lượng byte/giây thực tế (delta throughput theo giây) nhận qua WebSocket, không dùng số liệu ngẫu nhiên.
- **Threat Incidents & Inspect Modal:** Hiển thị thẻ MITRE ATT&CK cho từng cảnh báo; nút "Inspect" mở cửa sổ phân tích ngữ cảnh hiển thị 50 gói tin tương quan (±5 phút quanh thời điểm phát hiện).
- **Phân quyền vai trò người dùng (RBAC):**
  - `Admin`: Toàn quyền cấu hình rule, kênh thông báo, xem audit log, chặn/bỏ chặn IP. (Chưa có giao diện quản lý người dùng; tài khoản tự đăng ký luôn là `Viewer`.)
  - `Analyst`: Xem cảnh báo, xác nhận (Acknowledge), đóng (Resolve) và mở lại sự cố; xem blocklist (chỉ đọc).
  - `Viewer`: Chế độ chỉ đọc (Read-only); các nút thao tác bị ẩn/vô hiệu hóa an toàn.
- **URL Hash Synchronization:** Hỗ trợ đồng bộ tab với URL (`#dashboard`, `#alerts`, `#traffic`, `#rules`, `#devices`, `#blocklist`, `#settings`, `#audit_logs`).
- **Audit Logs View:** Trang quản trị nhật ký kiểm toán cho Admin, truy vết toàn bộ hành vi sửa luật, đổi cấu hình, xử lý sự cố.
- **Sensor Health Indicator:** Trạng thái sensor trên Dashboard (Healthy / Degraded / Failed / Offline) dựa trên heartbeat 15 giây với số gói bắt được/bị rơi thực tế.

---

## 🧪 6. Kết quả Đánh giá Thực nghiệm (Precision, Recall & Throughput)

Bộ test suite tự động tích hợp sẵn benchmark đo lường:

```bash
nix develop --command cargo test --test benchmark_evaluation_test -- --nocapture
```

### Kết quả đo lường:
- **Thông lượng xử lý (Pipeline Throughput):** $> 220,000$ packets/giây trên phần cứng thông thường.
- **Độ chính xác (Precision):** **100%** (0 false positives trên 500 gói tin lưu lượng bình thường gồm SSH typing, DNS web thông thường, NTP).
- **Độ nhạy (Recall):** **100%** (phát hiện đầy đủ 4/4 kịch bản tấn công giả lập: Port Scan, SYN Flood, Brute Force, DNS Tunnel).
- **F1-Score:** **1.0000**.

---

## 🚀 7. Hướng dẫn Khởi chạy & Triển khai

> Người dùng **Windows** xem hướng dẫn riêng: [`WINDOWS_DOCKER_GUIDE.md`](WINDOWS_DOCKER_GUIDE.md).

### Cách 1: Chạy toàn bộ bằng Docker Compose trên NixOS / Linux (Khuyên dùng)

Không cần cài Rust, Trunk hay PostgreSQL trên máy. Mọi thứ được biên dịch và chạy trong container.

#### Bước 1: Bật Docker trên NixOS

Thêm vào `/etc/nixos/configuration.nix`:

```nix
virtualisation.docker.enable = true;

users.users.<tên_user>.extraGroups = [ "docker" ];   # chạy docker không cần sudo
```

Áp dụng cấu hình, rồi **đăng xuất và đăng nhập lại** để nhóm `docker` có hiệu lực:

```bash
sudo nixos-rebuild switch
```

Kiểm tra (NixOS đã kèm sẵn plugin `docker compose` v2):

```bash
docker version          # phải hiện cả Client và Server
docker compose version
id -nG                  # phải có "docker"
```

> Trên Linux khác (Ubuntu, Debian, Fedora…): cài Docker Engine + Compose plugin theo https://docs.docker.com/engine/install/, rồi chạy `sudo usermod -aG docker $USER`.

#### Bước 2: Lấy mã nguồn và tạo file `.env` (tuỳ chọn)

```bash
git clone <url-repo> Real-time-Network-Security-Analytics-Alerting-System
cd Real-time-Network-Security-Analytics-Alerting-System
cp .env.example .env    # tuỳ chọn: không có .env thì docker-compose.yml dùng giá trị mặc định
```

Các biến quan trọng trong `.env` (đều có mặc định an toàn cho môi trường dev):

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `postgres` / `postgres` / `network_security` | Tài khoản CSDL TimescaleDB |
| `POSTGRES_PORT` | `5432` | Cổng CSDL mở ra máy host (chỉ `127.0.0.1`) |
| `REDIS_PASSWORD` | `secnet_redis_dev_password` | Mật khẩu Redis |
| `JWT_SECRET` | chuỗi dev | **Bắt buộc đổi khi `ENVIRONMENT=production`** (`openssl rand -hex 32`) |
| `SIMULATION_MODE` | `true` | `true` = sinh lưu lượng giả lập; `false` = bắt gói tin thật |
| `DEMO_SCENARIO` | `all` | Kịch bản tấn công giả lập (xem Bước 6) |
| `AUTO_BLOCK_CRITICAL_IPS` | `true` | Tự chặn IP gây cảnh báo Critical |

> Các biến `SMTP_*`, `TELEGRAM_*`, `WEBHOOK_DEFAULT_URL` trong `.env.example` **không được dùng**. Kênh thông báo được cấu hình trên giao diện web (xem Bước 5).

#### Bước 3: Build và khởi chạy

```bash
docker compose up -d --build
```

Lần đầu mất khoảng 5–15 phút để tải image và biên dịch Rust ở chế độ release. Các lần sau nhanh hơn nhờ cache. Lệnh này khởi động **6 container** trong mạng `secnet_mesh`:

| Container | Cổng trên máy host | Chức năng |
|---|---|---|
| `secnet_timescaledb` | `127.0.0.1:5432` | PostgreSQL 15 + TimescaleDB 2.14.2 |
| `secnet_redis` | `127.0.0.1:6379` | Cache / throttling cảnh báo phân tán |
| `secnet_backend` | `127.0.0.1:8080` | REST API Axum + WebSocket. Tự chạy toàn bộ migration (kèm dữ liệu mẫu và tài khoản) khi khởi động |
| `secnet_frontend` | `127.0.0.1:3000` | Dashboard Leptos WASM phục vụ bởi Nginx |
| `secnet_nginx_tls` | `0.0.0.0:80`, `0.0.0.0:443` | Reverse proxy TLS. Tự sinh chứng chỉ tự ký vào `deploy/nginx/certs/` lần đầu. Cổng 80 chuyển hướng sang 443 |
| `secnet_capture_engine` | (nội bộ) | Bắt gói tin / giả lập tấn công, chạy 8 luật phát hiện |

#### Bước 4: Kiểm tra trạng thái

```bash
docker compose ps
curl http://127.0.0.1:8080/health     # {"service":"secnet-backend","status":"ok"}
```

Mọi container phải ở trạng thái `Up`. `timescaledb`, `redis`, `backend`, `frontend` hiển thị thêm `(healthy)`.

#### Bước 5: Truy cập web và đăng nhập

| Thành phần | URL | Ghi chú |
|---|---|---|
| **Dashboard (HTTPS)** | https://localhost | Qua Nginx TLS. Dùng được từ máy khác trong mạng: `https://<IP-máy-chủ>` |
| **Dashboard (HTTP)** | http://localhost:3000 | Chỉ truy cập được từ chính máy chạy Docker |
| **Swagger UI** | http://localhost:8080/swagger-ui/ | Tắt khi `ENVIRONMENT=production` (trừ khi `ENABLE_SWAGGER=true`) |
| **Prometheus metrics** | http://localhost:8080/metrics | Đặt `METRICS_TOKEN` để yêu cầu Bearer token |

Chứng chỉ HTTPS là tự ký nên trình duyệt sẽ cảnh báo. Trên Firefox chọn **Advanced… → Accept the Risk and Continue**, trên Chrome chọn **Advanced → Proceed to localhost (unsafe)**.

Mở nhanh từ terminal: `firefox https://localhost &`

**🔑 Tài khoản có sẵn** (tạo bởi migration `20260101000011_seed_sample_data.sql`):

| Vai trò | Username | Mật khẩu | Quyền |
|---|---|---|---|
| **Admin** | `admin` | `Admin@SecNet2026!` | Toàn quyền: luật phát hiện, kênh thông báo, blocklist, audit log |
| **Analyst** | `analyst` hoặc `analyst_linh` | `Analyst@SecNet2026!` | Xác nhận / đóng / mở lại sự cố, xem blocklist (chỉ đọc) |
| **Viewer** | `viewer` hoặc `viewer_demo` | `Viewer@SecNet2026!` | Chỉ xem |

**Tài khoản CSDL / Redis** (chỉ mở trên `127.0.0.1`):

| Dịch vụ | Kết nối |
|---|---|
| PostgreSQL | `postgres://postgres:postgres@localhost:5432/network_security` (hoặc `docker exec -it secnet_timescaledb psql -U postgres -d network_security`) |
| Redis | `redis://:secnet_redis_dev_password@localhost:6379` |

> ⚠️ Đây là mật khẩu dùng cho dev/demo. Khi triển khai thật, đổi mật khẩu các tài khoản web, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET` và đặt `ENVIRONMENT=production`. Tài khoản tự đăng ký trên trang web luôn có vai trò `Viewer`.

#### Bước 6: Cấu hình gửi cảnh báo qua Email (Gmail)

1. Bật **Xác minh 2 bước** cho tài khoản Gmail dùng để gửi.
2. Tạo **App Password** tại https://myaccount.google.com/apppasswords (16 ký tự).
3. Đăng nhập `admin`, vào mục **Alert channels** ở thanh bên trái, bấm **Add channel**, chọn Channel type **Email (SMTP)**, điền rồi bấm **Save channel**:

| Ô | Giá trị |
|---|---|
| SMTP Host | `smtp.gmail.com` |
| Port | `587` |
| Connection security | `STARTTLS (587/2525)` |
| Username | Địa chỉ Gmail gửi, đầy đủ `@gmail.com` |
| Password | App Password 16 ký tự, viết liền (**không** phải mật khẩu Gmail) |
| From address | Để trống (hệ thống dùng Username) |
| Recipient Email (To) | Hộp thư nhận cảnh báo (mỗi kênh một địa chỉ) |

4. Bấm **Send test alert** để kiểm tra. Lỗi `530 Authentication required` nghĩa là thiếu Username/Password; lỗi `535` nghĩa là sai App Password. Giao diện chưa có chức năng sửa kênh, muốn đổi cấu hình thì xoá kênh rồi tạo lại.

#### Bước 7: Chọn kịch bản tấn công giả lập

Mặc định (`DEMO_SCENARIO=all`) capture-engine luân phiên đủ 8 kịch bản. Để chạy một kịch bản cố định:

```bash
DEMO_SCENARIO=syn_flood docker compose up -d capture-engine
```

Giá trị hợp lệ: `all`, `none`, `port_scan`, `syn_flood`, `brute_force`, `arp_spoof`, `dns_tunneling`, `volume_spike`, `icmp_flood`, `beaconing`.

#### Kiểm thử toàn bộ tính năng trên hệ thống đang chạy

Script `scripts/test_system.ps1` (Windows gọi qua `test.bat`) kiểm tra khoảng 90 mục: container, API, web, TLS, CSDL, đăng nhập, RBAC, WebSocket, phát hiện tấn công, luật, blocklist, kênh thông báo. Mô tả chi tiết ở mục 7 của [`WINDOWS_DOCKER_GUIDE.md`](WINDOWS_DOCKER_GUIDE.md). Trên NixOS chạy bằng PowerShell 7:

```bash
nix shell nixpkgs#powershell --command pwsh -File scripts/test_system.ps1                      # nhanh (~1 phút)
nix shell nixpkgs#powershell --command pwsh -File scripts/test_system.ps1 -SendNotifications   # + gửi thật qua kênh đang bật
nix shell nixpkgs#powershell --command pwsh -File scripts/test_system.ps1 -Full                # + cargo test trong Docker
```

Kết quả được lưu vào `test_report.txt`.

#### Bước 8: Các lệnh quản lý thường dùng

```bash
docker compose logs -f                    # log toàn hệ thống
docker compose logs -f backend            # log backend (xem lỗi gửi email tại đây)
docker compose logs -f capture-engine     # log bắt gói / phát hiện
docker compose restart backend            # khởi động lại một dịch vụ
docker compose up -d --build backend frontend   # build lại sau khi sửa code
docker compose stop                       # tạm dừng (giữ dữ liệu)
docker compose start                      # chạy lại
docker compose down                       # xoá container (giữ dữ liệu trong volume)
docker compose down -v                    # xoá cả CSDL, lần chạy sau nạp lại dữ liệu mẫu
```

#### Xử lý sự cố trên NixOS / Linux

| Triệu chứng | Cách xử lý |
|---|---|
| `permission denied while trying to connect to the Docker daemon socket` | User chưa ở nhóm `docker`: thêm vào `extraGroups`, `nixos-rebuild switch`, đăng xuất rồi đăng nhập lại |
| `Cannot connect to the Docker daemon` | `sudo systemctl start docker` (kiểm tra `virtualisation.docker.enable = true`) |
| `port is already allocated` (5432 / 6379 / 8080 / 80 / 443) | Tắt dịch vụ đang chiếm cổng (`sudo ss -ltnp \| grep :5432`), hoặc đổi `POSTGRES_PORT` / `REDIS_PORT` trong `.env` |
| Không vào được `https://<IP>` từ máy khác | Mở tường lửa NixOS: `networking.firewall.allowedTCPPorts = [ 80 443 ];` |
| Backend không lên, log báo lỗi migration | Xoá CSDL cũ và tạo lại: `docker compose down -v && docker compose up -d --build` |
| Web hiển thị giao diện cũ sau khi build lại | Tải lại trang bỏ cache: `Ctrl+Shift+R` |

### Cách 2: Chạy trực tiếp qua Nix Flake (Development)
```bash
# 1. Kích hoạt môi trường Nix
nix develop

# 2. Khởi chạy CSDL & Redis nền
docker compose up -d timescaledb redis

# 3. Khởi chạy Backend API
cargo run -p backend

# 4. Khởi chạy Capture Engine
cargo run -p capture-engine

# 5. Khởi chạy Frontend Web (proxy /api và /ws sang :8080, xem Trunk.toml)
./run_frontend.sh
```

---

## 🧪 8. Chạy Toàn bộ Bộ Kiểm thử (46 Tests)

```bash
# Kiểm tra định dạng code chuẩn
nix develop --command cargo fmt --all -- --check

# Kiểm tra cảnh báo linter
nix develop --command cargo clippy --all-targets -- -D warnings

# Chạy toàn bộ bài kiểm thử (đặt DATABASE_URL để chạy cả test tích hợp với TimescaleDB)
docker compose up -d timescaledb
DATABASE_URL=postgres://postgres:postgres@localhost:5432/network_security nix develop --command cargo test --workspace
```

Danh mục bài kiểm thử:
- `api_db_tests`: Test tích hợp handler với DB thật — CRUD rule, vòng đời sự cố, blocklist, che secret, heartbeat, lockout, lưu DNS dài, dashboard (8 tests; bỏ qua nếu thiếu `DATABASE_URL`).
- `detection_tests`: 8 thuật toán phát hiện, ARP theo IP người gửi, SYN flood phân tán, chống lặp DNS, rule xoá/tuỳ chỉnh, simulator phủ đủ 8 detector, snapshot & restore (16 tests).
- `benchmark_evaluation_test`: Throughput benchmark + Precision/Recall (2 tests).
- `alert_multichannel_simulation_test`: Email/Webhook/Telegram với mock server và xử lý lỗi (2 tests).
- `alerting_tests`: Kênh thông báo và throttling (2 tests).
- `api_integration_tests`: RBAC, JWT, Argon2id, tách access/refresh token (4 tests).
- `rate_limit_tests`: Xác định IP client tin cậy, chống giả mạo `X-Real-IP` (3 tests).
- `webhook_ssrf_tests`: Chặn SSRF vào dải IP riêng tư (4 tests).
- `model_tests`: DTOs, Enums, IP network serialization (5 tests).

---

## 💾 9. Sao lưu & Phục hồi CSDL (Disaster Recovery)

Hệ thống cung cấp script sao lưu tự động hỗ trợ TimescaleDB hypertables và chính sách lưu trữ 7 ngày:
```bash
# Thực hiện sao lưu ngay lập tức
./scripts/backup_db.sh
```
Bản sao lưu nén gzip sẽ được lưu tại thư mục `./backups/secnet_backup_YYYYMMDD_HHMMSS.sql.gz`.
